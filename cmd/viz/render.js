var eventIndex = 0;
var currentState = {
  objects: [],
  edges: []
};
var dotIndex = 0;
var graphviz = d3.select("#graph").graphviz().growEnteringEdges(true)
    .transition(function () {
        return d3.transition("main")
            .ease(d3.easeLinear)
            .delay(100)
            .duration(100);
    })
    .logEvents(true);

function render() {
    var dot = dots.pop().join('');
    graphviz
        .renderDot(dot)
        .on("end", function () {
            getEvent();
        });
}

function renderState(state) {
  return `digraph {
  newrank=true;
  rankdir=LR;

  subgraph cluster_manifests {
    label = "Manifests";
    " " [style=invis];

    ${renderManifests(state)}
  }

  subgraph cluster_blobs {
    label = "Blobs";
    "  " [style=invis];

    ${renderNodes(state, "Blob")}
  }

  subgraph cluster_uploads {
    label = "Uploads";
    "   " [style=invis];

    ${renderNodes(state, "Upload")}
  }

  ${renderEdges(state)}
}`;
}

// TODO: This should be slightly different for image index.
// Rank should not be the same.
function renderManifests(state) {
  return renderNodes(state, "Manifest");
}

function renderNodes(state, kind) {
  let objs = [];
  for (let obj of state.objects) {
    if (obj.Kind == kind) {
      let s = `"${obj.Identifier}"`;
      if (obj.color) {
        s += ` [color="${obj.color}", penwidth=2]`;
      }
      objs.push(s);
    }
  }

  return `{
    rank=same;

    ${objs.join(';')}
  }`;
}

function renderEdges(state) {
  let edges = [];
  for (let edge of state.edges) {
    let s = `"${edge.src}" -> "${edge.dst}"`;
    if (edge.color) {
      s += ` [color="${edge.color}"]`;
    }
    edges.push(s);
  }

  // TODO If no edges, add invisible edges?
  return `${edges.join(';')}`;
}

var colors = {
  0: "orange",
  200: "green",
  201: "blue",
  202: "yellow",
  404: "red"
};

function match(obj, e) {
  return obj.Kind == e.Kind && obj.Identifier == e.Identifier && obj.Repo == e.Repo;
}

// (state, event) => state
function updateState(state, e) {
  let nodeFound = false;
  let missing = [...e.Objects];

  // Update existing node.
  for (let obj of state.objects) {
    if (!nodeFound && match(obj, e)) {
      obj.color = colors[e.Status] || "black";
      nodeFound = true;
      continue;
    }

    // Not updated.
    delete obj.color;
  }

  // Update existing edges.
  outer:
  for (let edge of state.edges) {
    for (let i = 0; i < missing.length; i++) {
      if match(edge.dst, missing[i]) {
        edge.color = colors[e.Status];
        missing.splice(i, 1);
        continue outer;
      }
    }
    
    // Not updated.
    delete edge.color;
  }

  // Add missing node.
  if (!nodeFound) {
    let obj = {
      Kind: e.Kind,
      Identifier: e.Identifier,
      Repo: e.Repo,
      color: colors[e.Status]
    }
    state.objects.push(obj);
  }

  // Add missing edges.
  for (let target of missing) {
    let edge = {
      src: {
        Kind: e.Kind,
        Identifier: e.Identifier,
        Repo: e.Repo
      },
      dst: {
        Kind: target.Kind,
        Identifier: target.Identifier,
        Repo: target.Repo
      },
      color: colors[e.Status];
    };
    state.edges.push(edge);
  }
}

function getEvent() {
  fetch('/events/' + eventIndex)
    .then(response => response.json())
    .then(function(e) {
      currentState = updateState(currentState, e);
      dots.push(renderState(currentState));
      eventIndex++;
    });
}

getEvent();
</script>
