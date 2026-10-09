use std::io;

use crate::route::{parse_route, Route};
use crate::{read_i32, read_u16, read_u32, DumpError, HDR, NLMSG_DONE, NLMSG_ERROR, RTM_NEWROUTE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Done,
    Ack,
    Route(Route),
    Ignore,
}

pub fn parse_msg(buf: &[u8]) -> Result<Msg, DumpError> {
    let len = read_u32(buf, 0)? as usize;
    if len < HDR || len > buf.len() {
        return Err(DumpError::Truncated);
    }
    let msg = buf.get(..len).ok_or(DumpError::Truncated)?;
    match read_u16(msg, 4)? {
        NLMSG_DONE => Ok(Msg::Done),
        NLMSG_ERROR => parse_error(msg),
        RTM_NEWROUTE => Ok(Msg::Route(parse_route(msg)?)),
        _ => Ok(Msg::Ignore),
    }
}

fn parse_error(msg: &[u8]) -> Result<Msg, DumpError> {
    let err = read_i32(msg, HDR)?;
    if err == 0 {
        return Ok(Msg::Ack);
    }
    Err(DumpError::Kernel(io::Error::from_raw_os_error(-err)))
}
