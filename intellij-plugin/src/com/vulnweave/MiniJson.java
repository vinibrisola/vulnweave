package com.vulnweave;

import java.util.*;

final class MiniJson {
    private final String s; private int i;
    private MiniJson(String s){this.s=s;}
    static Object parse(String s){ MiniJson p=new MiniJson(s); Object v=p.value(); p.ws(); if(p.i!=p.s.length()) throw new IllegalArgumentException("Trailing JSON at "+p.i); return v; }
    static String stringify(Object v){ StringBuilder b=new StringBuilder(); write(b,v); return b.toString(); }
    private static void write(StringBuilder b,Object v){
        if(v==null){b.append("null");return;} if(v instanceof String){b.append('"');for(char c:((String)v).toCharArray()){switch(c){case '"':b.append("\\\"");break;case '\\':b.append("\\\\");break;case '\n':b.append("\\n");break;case '\r':b.append("\\r");break;case '\t':b.append("\\t");break;default:if(c<32)b.append(String.format("\\u%04x",(int)c));else b.append(c);}}b.append('"');return;}
        if(v instanceof Number||v instanceof Boolean){b.append(v);return;} if(v instanceof Map){b.append('{');boolean f=true;for(Object e0:((Map<?,?>)v).entrySet()){Map.Entry<?,?> e=(Map.Entry<?,?>)e0;if(!f)b.append(',');f=false;write(b,String.valueOf(e.getKey()));b.append(':');write(b,e.getValue());}b.append('}');return;} if(v instanceof Iterable){b.append('[');boolean f=true;for(Object x:(Iterable<?>)v){if(!f)b.append(',');f=false;write(b,x);}b.append(']');return;} write(b,String.valueOf(v));
    }
    private Object value(){ws();if(i>=s.length())err("EOF");char c=s.charAt(i);if(c=='{')return obj();if(c=='[')return arr();if(c=='"')return str();if(c=='t'&&take("true"))return true;if(c=='f'&&take("false"))return false;if(c=='n'&&take("null"))return null;return num();}
    private Map<String,Object> obj(){expect('{');LinkedHashMap<String,Object> m=new LinkedHashMap<>();ws();if(peek('}')){i++;return m;}while(true){ws();String k=str();ws();expect(':');m.put(k,value());ws();if(peek('}')){i++;return m;}expect(',');}}
    private List<Object> arr(){expect('[');ArrayList<Object>a=new ArrayList<>();ws();if(peek(']')){i++;return a;}while(true){a.add(value());ws();if(peek(']')){i++;return a;}expect(',');}}
    private String str(){expect('"');StringBuilder b=new StringBuilder();while(i<s.length()){char c=s.charAt(i++);if(c=='"')return b.toString();if(c=='\\'){if(i>=s.length())err("escape");char e=s.charAt(i++);switch(e){case '"':b.append('"');break;case '\\':b.append('\\');break;case '/':b.append('/');break;case 'b':b.append('\b');break;case 'f':b.append('\f');break;case 'n':b.append('\n');break;case 'r':b.append('\r');break;case 't':b.append('\t');break;case 'u':if(i+4>s.length())err("unicode");b.append((char)Integer.parseInt(s.substring(i,i+4),16));i+=4;break;default:err("escape");}}else b.append(c);}err("string");return "";}
    private Number num(){int st=i;if(peek('-'))i++;while(i<s.length()&&Character.isDigit(s.charAt(i)))i++;if(peek('.')){i++;while(i<s.length()&&Character.isDigit(s.charAt(i)))i++;}if(i<s.length()&&(s.charAt(i)=='e'||s.charAt(i)=='E')){i++;if(peek('+')||peek('-'))i++;while(i<s.length()&&Character.isDigit(s.charAt(i)))i++;}String n=s.substring(st,i);try{return n.contains(".")||n.contains("e")||n.contains("E")?Double.valueOf(n):Long.valueOf(n);}catch(Exception e){err("number");return 0;}}
    private boolean take(String x){if(s.startsWith(x,i)){i+=x.length();return true;}return false;}private boolean peek(char c){return i<s.length()&&s.charAt(i)==c;}private void expect(char c){ws();if(!peek(c))err("expected "+c);i++;}private void ws(){while(i<s.length()&&Character.isWhitespace(s.charAt(i)))i++;}private void err(String m){throw new IllegalArgumentException(m+" at "+i);}
    @SuppressWarnings("unchecked") static Map<String,Object> map(Object o){return (Map<String,Object>)o;} @SuppressWarnings("unchecked") static List<Object> list(Object o){return o instanceof List?(List<Object>)o:Collections.emptyList();}
    static String str(Map<String,Object> m,String k){Object v=m.get(k);return v==null?"":String.valueOf(v);} static boolean bool(Map<String,Object>m,String k){Object v=m.get(k);return v instanceof Boolean?(Boolean)v:Boolean.parseBoolean(String.valueOf(v));} static double dbl(Map<String,Object>m,String k){Object v=m.get(k);return v instanceof Number?((Number)v).doubleValue():0.0;}
}
