import { useState, useEffect } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Search, X, History, Filter, Info } from "lucide-react";
import {
  QUICK_FILTERS,
  getFilterHistory,
  saveFilterToHistory,
  clearFilterHistory,
} from "@/lib/packet-filter";
import { Card } from "@/components/ui/card";

interface PacketFilterProps {
  value: string;
  onChange: (filter: string) => void;
  resultCount?: number;
  totalCount?: number;
}

export function PacketFilter({
  value,
  onChange,
  resultCount,
  totalCount,
}: PacketFilterProps) {
  const [inputValue, setInputValue] = useState(value);
  const [history, setHistory] = useState<string[]>([]);
  const [showHelp, setShowHelp] = useState(false);

  useEffect(() => {
    setHistory(getFilterHistory());
  }, []);

  useEffect(() => {
    setInputValue(value);
  }, [value]);

  const handleApplyFilter = () => {
    onChange(inputValue);
    if (inputValue.trim()) {
      saveFilterToHistory(inputValue);
      setHistory(getFilterHistory());
    }
  };

  const handleClearFilter = () => {
    setInputValue('');
    onChange('');
  };

  const handleQuickFilter = (filter: string) => {
    setInputValue(filter);
    onChange(filter);
    saveFilterToHistory(filter);
    setHistory(getFilterHistory());
  };

  const handleHistoryClick = (filter: string) => {
    setInputValue(filter);
    onChange(filter);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleApplyFilter();
    } else if (e.key === 'Escape') {
      handleClearFilter();
    }
  };

  return (
    <div className="space-y-3">
      {/* Search Bar */}
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={handleKeyPress}
            placeholder="Filter packets (e.g., ip.src == 192.168.1.1, protocol == HTTP, port contains 443)"
            className="pl-9 pr-20"
          />
          {inputValue && (
            <Button
              variant="ghost"
              size="sm"
              onClick={handleClearFilter}
              className="absolute right-1 top-1/2 -translate-y-1/2 h-7"
            >
              <X className="h-4 w-4" />
            </Button>
          )}
        </div>

        <Button onClick={handleApplyFilter} size="default">
          <Filter className="mr-2 h-4 w-4" />
          Apply
        </Button>

        {/* History Popover */}
        {history.length > 0 && (
          <Popover>
            <PopoverTrigger asChild>
              <Button variant="outline" size="default">
                <History className="h-4 w-4" />
              </Button>
            </PopoverTrigger>
            <PopoverContent className="w-80" align="end">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="font-semibold text-sm">Filter History</h4>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      clearFilterHistory();
                      setHistory([]);
                    }}
                  >
                    Clear
                  </Button>
                </div>
                <div className="space-y-1">
                  {history.map((filter, index) => (
                    <button
                      key={index}
                      onClick={() => handleHistoryClick(filter)}
                      className="w-full text-left text-sm p-2 rounded hover:bg-muted transition-colors font-mono"
                    >
                      {filter}
                    </button>
                  ))}
                </div>
              </div>
            </PopoverContent>
          </Popover>
        )}

        {/* Help Popover */}
        <Popover open={showHelp} onOpenChange={setShowHelp}>
          <PopoverTrigger asChild>
            <Button variant="outline" size="default">
              <Info className="h-4 w-4" />
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-96" align="end">
            <div className="space-y-3">
              <h4 className="font-semibold">Filter Syntax</h4>
              <div className="space-y-2 text-sm">
                <div>
                  <p className="font-medium">Fields:</p>
                  <code className="text-xs block bg-muted p-2 rounded mt-1">
                    ip.src, ip.dst, ip.addr, protocol, port, length, info
                  </code>
                </div>
                <div>
                  <p className="font-medium">Operators:</p>
                  <code className="text-xs block bg-muted p-2 rounded mt-1">
                    ==, !=, contains, matches, {'>'}, {'<'}, {'>='},{'<='}
                  </code>
                </div>
                <div>
                  <p className="font-medium">Examples:</p>
                  <ul className="text-xs space-y-1 mt-1 list-disc list-inside">
                    <li><code>ip.src == 192.168.1.1</code></li>
                    <li><code>protocol == HTTP</code></li>
                    <li><code>port contains 443</code></li>
                    <li><code>length {'>'} 1000</code></li>
                    <li><code>info contains error</code></li>
                    <li><code>ip.addr matches 192.168.*</code></li>
                  </ul>
                </div>
              </div>
            </div>
          </PopoverContent>
        </Popover>
      </div>

      {/* Quick Filters */}
      <div className="flex flex-wrap gap-2">
        {QUICK_FILTERS.map((qf) => (
          <Badge
            key={qf.filter}
            variant={inputValue === qf.filter ? "default" : "outline"}
            className="cursor-pointer hover:bg-primary hover:text-primary-foreground transition-colors"
            onClick={() => handleQuickFilter(qf.filter)}
          >
            <span className="mr-1">{qf.icon}</span>
            {qf.label}
          </Badge>
        ))}
      </div>

      {/* Results Count */}
      {resultCount !== undefined && totalCount !== undefined && (
        <Card className="p-3 bg-muted/50">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">
              {value ? 'Filtered Results:' : 'Total Packets:'}
            </span>
            <span className="font-semibold">
              {resultCount.toLocaleString()}
              {value && totalCount !== resultCount && (
                <span className="text-muted-foreground ml-1">
                  of {totalCount.toLocaleString()}
                </span>
              )}
            </span>
          </div>
        </Card>
      )}
    </div>
  );
}
