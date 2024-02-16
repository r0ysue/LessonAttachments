from trail import get_trail
def getMouseEvent(trail: list):
    eventList = []
    mousedown = {
        "type": "mousedown",
        "clientX": trail[0][0],
        "clientY": trail[0][1],
        "time": trail[0][2],
    }
    eventList.append(mousedown)
    for single_trail in trail:
        x = single_trail[0]
        y = single_trail[1]
        t = single_trail[2]
        eventList.append({
            "type": "mousemove",
            "clientX": x,
            "clientY": y,
            "time": t
        })
    mouseup = {
        "type": "mouseup",
        "clientX": trail[-1][0],
        "clientY": trail[-1][1],
        "time": trail[-1][2],
    }
    eventList.append(mouseup)
    return eventList


if __name__ == '__main__':
    trail = get_trail(100)
    print(getEvent(trail))
