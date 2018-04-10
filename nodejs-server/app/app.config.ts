export class AppConfig {
    public static secret = 'randomstr-efr23fe2r3fegrbnj65645rfghuy4t4gh56r4fw924f9ue1)HG(&F&%"/FT)';
    public static tokenExpirationTime = 240;  // in Minutes    
    public static mongoDB = 'mongodb://172.17.0.5:27017/tictactoeDB'; 
    public static restAPIPort = '7777';
    public static restAPIPrefix = (version : string = '1') => '/v' + version + '/';    
    public static restAPIFullPrefix = (version : string = '1') => ':' + AppConfig.restAPIPort + '/v' + version + '/';   
    public static hostname = 'http://159.89.11.141';
}