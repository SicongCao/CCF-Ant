package tabby.taintAnalysis;

import java.util.ArrayList;
import java.util.List;

public class SingleLine {
    private String lineID;
    private String target;
    private String source;
    private ArrayList<Integer> pollutedPosition;
    private boolean isUsed;

    public SingleLine(String lineID,String target,String source) {
        this.lineID = lineID;
        this.source = source;
        this.target = target;
        this.isUsed = false;
    }


    public void setSource(String source) {
        this.source = source;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public void setIsUsed() {
        this.isUsed = true;
    }

    public void setPollutedPosition(ArrayList<Integer> pollutedPosition) {
        this.pollutedPosition = pollutedPosition;
    }

    public ArrayList<Integer> getPollutedPosition() {
        return pollutedPosition;
    }


    public String getSource() {
        return source;
    }

    public String getTarget() {
        return target;
    }
}
