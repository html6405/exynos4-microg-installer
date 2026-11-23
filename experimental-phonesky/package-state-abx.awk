# Fail-closed ABX v0 inspector, derived from AOSP BinaryXmlPullParser/FastDataInput.
# Only exact legacy domain-history attributes may mention ecosystem package IDs.
function die() { bad=1; exit 3 }
function byte(v) { if(pos>count)die(); v=data[pos];pos++;return v }
function short(a,b) { a=byte(); b=byte(); return a*256+b }
function utf( n,s,i,c,k,j,d,first) {
 n=short(); if(pos+n-1>count)die(); s=""
 for(i=0;i<n;i++){
  c=byte();if(c==0)die();s=s sprintf("%c",c)
  if(c<128)continue
  if(c>=194&&c<=223)k=1
  else if(c>=224&&c<=239)k=2
  else if(c>=240&&c<=244)k=3
  else die()
  if(i+k>=n)die()
  for(j=1;j<=k;j++){
   d=byte();if(d<128||d>191)die()
   if(j==1&&((c==224&&d<160)||(c==240&&d<144)||(c==244&&d>143)))die()
   s=s sprintf("%c",d);i++
  }
 }
 return s
}
function intern( ref,s) {
 ref=short(); if(ref==65535){s=utf();if(poolcount<65535){pool[poolcount]=s;poolcount++};return s}
 if(!(ref in pool))die();return pool[ref]
}
function sensitive(s) { return index(s,"com.google.android.gms")||index(s,"com.android.vending")||index(s,"com.google.android.gsf") }
function exact(s) { return s=="com.google.android.gms"||s=="com.android.vending"||s=="com.google.android.gsf"||s=="com.google.android.gsf.login"||s=="com.google.android.gms.supervision" }
function path( i,p) {p="";for(i=1;i<=depth;i++)p=p "/" tags[i];return p}
function checkvalue(s,name) {
 if(!sensitive(s))return
 if(path()=="/packages/package" && name=="installInitiator" && s=="com.android.vending"){
  historical_source[depth]=1
  return
 }
 if(path()!="/packages/domain-verifications-legacy/user-states"||name!="packageName"||!exact(s))die()
}
{
 for(field=1;field<=NF;field++){
  if($field!~/^[0-9]+$/||$field<0||$field>255||count>=2097152)die()
  count++;data[count]=$field+0
 }
}
END {
 if(bad)exit 3
 pos=1;poolcount=0;depth=0;rootcount=0;started=0;ended=0;attribute_phase=0;tagserial=0
 if(byte()!=65||byte()!=66||byte()!=88||byte()!=0)die()
 while(pos<=count){
  event=byte();token=event%16;type=event-token
  if(token==0){if(started||rootcount||type!=16)die();started=1;continue}
  if(!started||ended)die()
  if(token==1){if(depth||rootcount!=1||type!=16||pos!=count+1)die();ended=1;continue}
  if(token==2){
   if(type!=48||depth>=128)die();name=intern()
   if(name!~/^[A-Za-z_][A-Za-z0-9_.-]*$/||sensitive(name))die()
   if(!depth){if(rootcount||name!="packages")die();rootcount++}
   depth++;tags[depth]=name;tagserial++;serials[depth]=tagserial;attribute_phase=1;continue
  }
  if(token==3){if(type!=48||!depth||intern()!=tags[depth])die();if(historical_source[depth]&&!source_uninstalled[depth])die();delete historical_source[depth];delete source_uninstalled[depth];delete tags[depth];delete serials[depth];depth--;attribute_phase=0;continue}
  if(token==15){
   if(!depth||!attribute_phase)die();name=intern()
   if(name!~/^[A-Za-z_][A-Za-z0-9_.-]*$/||sensitive(name)||(serials[depth] SUBSEP name) in seen)die();seen[serials[depth] SUBSEP name]=1
   if(type==32){value=utf();checkvalue(value,name)}
   else if(type==48){value=intern();checkvalue(value,name)}
   else if(type==192){if(name=="installInitiatorUninstalled")source_uninstalled[depth]=1}
   else if(type==16||type==208){}
   else if(type==64||type==80){lengthbytes=short();blob="";for(i=0;i<lengthbytes;i++)blob=blob sprintf("%c",byte());if(sensitive(blob))die()}
   else if(type==96||type==112||type==160){for(i=0;i<4;i++)byte()}
   else if(type==128||type==144||type==176){for(i=0;i<8;i++)byte()}
   else die()
   continue
  }
  # Packages settings need no entities, DTDs, comments or mixed text; reject.
  die()
 }
 if(!ended||depth||rootcount!=1)die()
 exit 0
}
