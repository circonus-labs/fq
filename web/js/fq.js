Array.prototype.equals = function (array) {
    if (!array) return false;
    if (this.length != array.length) return false;

    for (var i = 0, l=this.length; i < l; i++) {
        if (this[i] instanceof Array && array[i] instanceof Array) {
            if (!this[i].equals(array[i])) return false;       
        }           
        else if (this[i] != array[i]) { 
            return false;   
        }           
    }       
    return true;
}

function pretty_number(a) {
  var i = 0;
  var unit = '';
  if(a.toFixed === undefined) return a;
  while(i < 6 && a > 1024) { a = a/1024; i++; }
  switch(i) {
    case 1: unit = 'k'; break;
    case 2: unit = 'M'; break;
    case 3: unit = 'G'; break;
    case 4: unit = 'T'; break;
    case 5: unit = 'P'; break;
    case 6: unit = 'E'; break;
    default:
  }
  return a.toFixed(Math.min(i,3)) + unit;
}

function hexify(a) {
  return a.split(/|/)
          .map(function(a) {
            var r = a.charCodeAt(0).toString(16);
            if(r.length < 2) return "0" + r;
            return r;
          }).join('')
}
function $badge(n) {
  return $("<span class=\"badge\"/>").text(n);
}
function $label(n, type) {
  if(!type) type = "default";
  return $("<span class=\"label label-"+type+"\"/>").text(n);
}
function alphaKeys(obj) {
  var keys = []
  for(var key in obj) if(obj.hasOwnProperty(key)) keys.push(key);
  return keys.sort();
}
var last_stats = {}
var last_stats_time;
var current_stats_time;
function rate_calc(type, name, data, part) {
  if(!last_stats_time ||
     !last_stats[type] ||
     !last_stats[type][name]) return undefined;
  var dt = current_stats_time - last_stats_time;
  var dv = data[part] - last_stats[type][name][part];
  return (dv/dt)*1000; /* /ms -> /s */
}

function rate_queue_calc(type, name, data, i, part) {
  if(!last_stats_time ||
     !last_stats[type] ||
     !last_stats[type][name]) return undefined;
  if(last_stats[type][name].clients.length != data.length) return undefined;
  var dt = current_stats_time - last_stats_time;
  var dv = data[i][part] - last_stats[type][name].clients[i][part];
  return (dv/dt)*1000; /* /ms -> /s */
}

function update_exchange(name,detail) {
  var id = "exchange-" + hexify(name);
  var $tgt = $("div#" + id);
  if($tgt.length == 0) {
    if(name == "_aggregate") return;
    var $template = $("div#exchange-5f616767726567617465"); /* _aggregate */
    $tgt = $template.clone();
    $tgt.attr('id', id);
    $tgt.find('h4.panel-title').text(name);
    var $ip = $("#exchanges > div.row:last");
    $ip.append($tgt);
    if($ip.find(">div").length == 3) {
      $("div#exchanges").append($("<div class=\"row\"></div>"));
    }
  }
  ["no_exchange", "messages", "octets", "no_route", "routed", "dropped", "size_dropped"].forEach(function(attr) {
    var rate = rate_calc("exchanges", name, detail, attr);
    if(rate !== undefined)
      rate = parseFloat(rate).toFixed(0);
    else rate = "";
    var value = pretty_number(parseFloat(detail[attr]));
    if(/NaN/.test(value)) value = "";
    if(/NaN/.test(rate)) rate = "";
    var ctag = attr.replace(/_/g, "-");
    $tgt.find(".exchange-"+ctag).text(value);
    $tgt.find(".exchange-"+ctag+"-rate").text(rate);
  });
}

function update_routes(name,detail) {
  if(name == "_aggregate") return;
  var routes = $("#routes");
  var re = "route-exchange-" + hexify(name);
  var $panel = routes.find("#" + re);
  if($panel.length == 0) {
    $panel = $("#route-exchange-template").clone();
    $panel.attr('id', re);
    routes.append($panel);
    $panel.find(".exchange-name").text(name);
  } else {
    $panel = $($panel[0]);
  }
 
  $panel.find(".route-row").addClass("updating");
  var sortedRoutes = alphaKeys(detail);
  sortedRoutes.forEach(function(rid) {
    var r = detail[rid];
    var $route = $panel.find("#route-" + rid);
    if($route.length == 0) {
      $route = $("#route-detail-template").clone();
      $route.attr('id', "#route-" + rid);
      $panel.append($route);
    } else {
      $route = $($route[0]);
    }
    $route.find(".route-prefix").html($label(r.prefix || '[blank / no prefix]', "success"));
    $route.find(".route-mode").html($label(r.permanent ? "permanent" : "transient", r.permanent ? "primary" : "default"));
    var prog_sans_prefix = r.program.replace(/^prefix:"(?:\\.|[^"])*"\s*/, "");
    $route.find(".route-program").text(prog_sans_prefix || '[ no program / match all ]');
    $route.find(".route-invocations").text(pretty_number(parseInt(r.invocations)));
    $route.find(".route-avg-ns").text("" + r.avg_ns + "ns");
    $route.removeClass("updating");
  });
  
  $panel.find(".route-row.updating").remove();
}

function clear_exchanges() {
  $("#exchanges > div.row:not(:first-child)").remove()
  $("#exchanges > div.row > div.exchange-detail:not(:first-child)").remove();
  $("#routes").empty();
}

function mk_client(c) {
  return c.name;
}

function update_queue_row(name,detail) {
  var id = "queue-" + hexify(name);
  var $tgt = $("div#" + id);
  if($tgt.length == 0) {
    $tgt = $("#queue-template").clone();
    $tgt.attr('id', id);
    var $collapse = $tgt.find(".panel-collapse");
    $tgt.find(".panel-heading a").attr('aria-controls', id + "-clients").on('click',
      function() { $collapse.collapse('toggle'); }
    );
    $collapse.attr('id', id + "-clients");
    $("#queues").append($tgt);
    $(document).on('.data-api');
  }
 
  $tgt.find(".queue-name").text(name); 
  $tgt.find(".queue-type").empty()
    .append($label("type:" + detail.type, "success"));
  $tgt.find(".queue-exposure").empty()
    .append($label(detail.private?"private":"public",
                   detail.private?"default":"primary"));
  $tgt.find(".queue-policy").empty()
    .append($label("policy:" + detail.policy, "danger"));

  var dropoutrate = rate_calc("queues", name, detail, "dropped_to");
  if(dropoutrate !== undefined) dropoutrate = parseFloat(dropoutrate).toFixed(0);
  else dropoutrate = "";
  var dropoutvalue = pretty_number(parseFloat(detail.dropped_to));
  console.log(dropoutvalue, dropoutrate);
  $tgt.find(".queue-dropped-out-rate").text(dropoutrate);
  $tgt.find(".queue-dropped-out-value").text(dropoutvalue);

  var $pb = $tgt.find(".progress-bar");
  var pct = 0;
  if(detail.backlog_limit > 0) pct = Math.floor(100 * detail.backlog / detail.backlog_limit);
  $pb.attr("style", "width: " + pct + "%");
  $pb.attr('aria-valuemax', detail.backlog_limit);
  $pb.attr('aria-valuenow', detail.backlog);
  
  $pb.removeClass("progress-bar-success");
  $pb.removeClass("progress-bar-warning");
  $pb.addClass( pct > 75 ? "progress-bar-warning" : "progress-bar-success" );
  if(detail.backlog_limit > 0)
    $tgt.find(".backlog").text(detail.backlog + "/" + detail.backlog_limit);
  else
    $tgt.find(".backlog").text(detail.backlog);

  var $clients = $tgt.find("table.clients tbody");
  if($clients.find(">tr").length != detail.clients.length) {
    $clients.empty();
    detail.clients.forEach(function() {
      $clients.append($("#client-template").clone().removeAttr('id'));
    });
  }
  $clients = $tgt.find("table.clients tbody > tr");
  for(var i=0;i<$clients.length;i++) {
    var $c = $($clients[i]), c = detail.clients[i];
    $c.find(".client-user").text(c.user);
    $c.find(".client-address").text(c.remote_addr + ":" + c.remote_port);


    ["msgs_in", "octets_in", "msgs_out", "octets_out",
     "routed", "dropped", "size_dropped", "no_route", "no_exchange"].forEach(function(attr) {
      var rate = rate_queue_calc("queues", name, detail.clients, i, attr);
      if(rate !== undefined) rate = parseFloat(rate).toFixed(0);
      else rate = "";
      var value = pretty_number(parseFloat(c[attr]));
      var ctag = attr.replace(/_/g, "-");
      $c.find(".client-" + ctag + "-rate").text(rate);
      $c.find(".client-" + ctag + "-value").text(value);
    });
  }
}


function refresh_stats() {
  $.ajax("/stats.json").done(function (x) {
    if(!x) return;
    current_stats_time = Date.now();
    if(x.version) $("#fq-version").text(x.version);

    var sortedExchanges = alphaKeys(x.exchanges);
    if(!alphaKeys(last_stats.exchanges || {}).equals(sortedExchanges)) clear_exchanges();
    sortedExchanges.forEach(function(exchange) {
      update_exchange(exchange, x.exchanges[exchange]);
      update_routes(exchange, x.exchanges[exchange].routes);
    });

    var sortedQueues = alphaKeys(x.queues);
    if(!alphaKeys(last_stats.queues || {}).equals(sortedQueues))
      $("#queues").empty();
    sortedQueues.forEach(function(queue) {
      update_queue_row(queue, x.queues[queue]);
    });

    last_stats_time = current_stats_time;
    last_stats = x;
  });
}

setInterval(refresh_stats, 1000);
refresh_stats();
