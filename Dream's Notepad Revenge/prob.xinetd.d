service prob                                  
{                                             
    flags = REUSE                             
    disable = no                              
    socket_type = stream                      
    wait = no                                 
    user = root                               
    server = /usr/sbin/chroot                 
    server_args = --userspec=yisf:yisf --groups yisf /chroot /home/yisf/prob
    port = 1004                                                          
    protocol = tcp                                                     
}             