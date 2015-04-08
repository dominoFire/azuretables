library(RCurl)
library(digest)
library(XML)
#library(R.utils)
#library(plyr)

# returns string w/o leading or trailing whitespace
trim <- function (x) gsub("^\\s+|\\s+$", "", x)

table_hostname = function(storage_account) 
  sprintf('%s.table.core.windows.net', storage_account)

# Shared Key Lite auth
shared_key_lite_table = function(date, canonicalized_resource)
  sprintf('%s\n%s', date, canonicalized_resource)

# Shared Key auth
shared_key_table <- function(http_verb, content_md5, content_type, date, canonicalized_resource)
  paste(http_verb, content_md5, content_type, date, canonicalized_resource, sep='\n', collapse='')

# Signs the request
sign_request <- function(auth_mode, storage_account, string_to_sign) {
  key_decoded = base64Decode(storage_key)[[1]]
  #print(string_to_sign)
  signed = hmac(key_decoded, enc2utf8(string_to_sign), algo='sha256', raw=T)
  ret = sprintf('%s %s:%s', auth_mode, storage_account, base64Encode(signed)[[1]])
  return(ret)
}

canonicalized_header_string = function(http_header) {
  # 1. Retrieve all headers for the resource that begin with x-ms-, including the x-ms-date header.
  # NOTE: each header have to appear only once
  x_ms_headers = http_header[ grepl('x-ms-', names(http_header)) ]
  # 2. Convert each HTTP header name to lowercase.
  x_ms_headers_names = unique(tolower(names(x_ms_headers)))
  names(x_ms_headers) = x_ms_headers_names
  # 3. Sort the headers lexicographically by header name, in ascending order. Each header may appear only once in the string.
  x_ms_headers_names = sort(x_ms_headers_names)
  x_ms_headers = x_ms_headers[ x_ms_headers_names ]
  # 4. Unfold the string by replacing any breaking white space with a single space. 
  ret_string = paste(x_ms_headers_names, x_ms_headers, sep=':', collapse='\n')
  ret_string = sub(' +', ' ', ret_string, perl=T)
  # 5. Trim any white space around the colon in the header.
  # Finally, append a new line character to each canonicalized header in the resulting list.
  # Construct the CanonicalizedHeaders string by concatenating all headers in this list into a single string.
  ret_string = trim(ret_string)
  # Add final \n
  ret_string = sprintf('%s', ret_string)
  return(ret_string)
}

canonicalized_resource_string = function(storage_account, request_url) {
  request_url = utils::URLdecode(request_url)
  uri = XML::parseURI(uri = request_url)
  # 1. Beginning with an empty string (""), append a forward slash (/), 
  #    followed by the name of the account that owns the resource being accessed.
  # 2. Append the resource's encoded URI path, without any query parameters.
  ret = sprintf('/%s%s', storage_account, uri$path)
  # 3. Retrieve all query parameters on the resource URI, 
  #    including the comp parameter if it exists.
  qparams = strsplit(strsplit(uri$query, split='&')[[1]], split='=')
  qp = sapply(qparams, function(x) {r = x[2]; names(r) = x[1]; return(r)})
  qp_names = names(qp)
  # 4. Convert all parameter names to lowercase.
  qp_names = tolower(qp_names)
  names(qp) = qp_names
  # 5.  Sort the query parameters lexicographically by parameter name,
  #     in ascending order.
  qp_names = sort(qp_names)
  qp = qp[ qp_names ]
  qp_string = ifelse(length(qparams) > 0, paste('\n', names(qp), qp, sep = ':', collapse = ''), '')
  #TODO: multivalued params in query strings
  ret = sprintf('%s%s', ret, qp_string)
  return(ret)
}
  
list_tables <- function(storage_account, storage_key) {
  table_url = sprintf('https://%s/Tables', table_hostname(storage_account))
  http_verb = 'GET'
  gmt_date = format(Sys.time(), tz='GMT', format='%a, %d %b %Y %H:%M:%S GMT')
  http_header = c(Authorization=':D', 
                  `x-ms-date`=gmt_date,
                  `x-ms-version`='2014-02-14',
                  Date=gmt_date,
                  DataServiceVersion='1.0;NetFx',
                  Accept='application/atom+xml')
  auth = sign_request(auth_mode = 'SharedKey',
                      storage_account = storage_account,
                      shared_key_table(http_verb = http_verb, 
                                       content_md5 = '', 
                                       content_type = '', 
                                       date = http_header['x-ms-date'], 
                                       canonicalized_resource = canonicalized_resource_string(storage_account, table_url)))
  http_header['Authorization'] = auth
  body = RCurl::getURL(url = table_url, .opts = list(customrequest=http_verb, httpheader=http_header))
  doc = xmlTreeParse(body)
  root = xmlRoot(doc)
  R.utils::captureOutput({
    table_names = sapply(getNodeSet(root, '//d:TableName'), xmlValue)
  })
  return(table_names)
}

query_entities = function(storage_account, storage_key, table_name, include_azure_columns=FALSE) {
  table_url = sprintf('https://%s/%s()', table_hostname(storage_account), table_name)
  http_verb = 'GET'
  gmt_date = format(Sys.time(), tz='GMT', format='%a, %d %b %Y %H:%M:%S GMT')
  http_header = c(Authorization=':D', 
                  `x-ms-date`=gmt_date,
                  `x-ms-version`='2014-02-14',
                  Date=gmt_date,
                  DataServiceVersion='1.0;NetFx',
                  Accept='application/atom+xml')
  auth = sign_request(auth_mode = 'SharedKey',
                      storage_account = storage_account,
                      shared_key_table(http_verb = http_verb, 
                                       content_md5 = '', 
                                       content_type = '', 
                                       date = http_header['x-ms-date'], 
                                       canonicalized_resource = canonicalized_resource_string(storage_account, table_url)))
  http_header['Authorization'] = auth
  h = basicHeaderGatherer()
  body = RCurl::getURL(url = table_url, 
                       .opts = list(customrequest=http_verb, httpheader=http_header),
                       headerfunction = h$update)
  str(h$value())
  doc = xmlTreeParse(body)
  root = xmlRoot(doc)
  R.utils::captureOutput({ #Avoid annoying error messages
    entries = getNodeSet(root, "//*[starts-with(local-name(), 'entry')]")
    rows = lapply(entries, function(x) xmlChildren(xmlChildren(x)$content)[['m:properties']])
    values = lapply(rows, function(x) 
      unlist(sapply(xmlChildren(x), 
                    function(x) ifelse(length(x)==0, NA, xmlValue(x)) )))
  })
  df = data.frame(Reduce(rbind, values), stringsAsFactors = F, row.names=1:length(values))
  colnames(df) = gsub('^d.', '',  colnames(df))
  azure_colnames = c('PartitionKey', 'RowKey', 'Timestamp')
  if(!include_azure_columns & any(colnames(df) %in% azure_colnames))
    df = df[, !(colnames(df) %in% azure_colnames)]
  df = plyr::colwise(type.convert, as.is=T, na.strings=c(''))(df)
  #print(root)
  #write.table(body, file='test.txt')
  return(df)
}

#Test
storage_account = 'kuboliac'
storage_key = 'pzRK4LP/y1DlsO54tSyNa7TM9ex2O+FnklS1Xj3foQ/3rrDi/OynMb0yDjTDnekqdsoP2w5NcBCnKe/8Qas4Ug=='

table_names = list_tables(storage_account, storage_key)
print(table_names)
az_table = query_entities(storage_account, storage_key, 'gnreference')
print(head(az_table))
str(az_table)
