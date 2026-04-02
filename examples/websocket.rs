/*
 * Copyright Stalwart Labs LLC See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#[cfg(feature = "websockets")]
use jmap_client::{client::Client, core::set::SetObject, PushObject};

// Make sure the "websockets" feature is enabled!
#[cfg(feature = "websockets")]
async fn websocket() {
    // Connect to the JMAP server using Basic authentication
    let client = Client::new()
        .credentials(("john@example.org", "secret"))
        .connect("https://jmap.example.org")
        .await
        .unwrap();

    // Open a correlated websocket connection and receive push notifications.
    let ws = client.connect_ws_correlated().await.unwrap();

    // Create a mailbox over WS and await the correlated response directly.
    let mut request = client.build();
    let create_id = request
        .set_mailbox()
        .create()
        .name("WebSocket Test")
        .create_id()
        .unwrap();
    let mut response = ws.send(request).await.unwrap();
    let mailbox_id = response
        .pop_method_response()
        .unwrap()
        .unwrap_set_mailbox()
        .unwrap()
        .created(&create_id)
        .unwrap()
        .take_id();

    // Enable push notifications over WS.
    ws.enable_push_ws(None::<Vec<_>>, None::<&str>)
        .await
        .unwrap();

    // Make changes over standard HTTP and expect a push notification via WS.
    client
        .mailbox_update_sort_order(&mailbox_id, 1)
        .await
        .unwrap();
    if let Some(PushObject::StateChange { changed }) = ws.next_push().await.map(Result::unwrap) {
        println!("Received changes: {:?}", changed);
    } else {
        unreachable!()
    }
}

fn main() {
    #[cfg(feature = "websockets")]
    let _c = websocket();
}
