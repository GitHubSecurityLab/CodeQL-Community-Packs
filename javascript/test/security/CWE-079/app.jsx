import * as React from 'react';
import {
    useQueryParams,
    StringParam,
    NumberParam,
    ArrayParam,
    withDefault,
} from 'use-query-params';

const UseQueryParamsExample = () => {
    // something like: ?x=123&q=foo&filters=a&filters=b&filters=c in the URL
    const [query, setQuery] = useQueryParams({
        x: NumberParam,
        q: StringParam,
        filters: withDefault(ArrayParam, []),
    });
    const { x: num, q: searchQuery, filters } = query;

    return (
        <div>
            <h1>num is {num}</h1>
            <button onClick={() => setQuery({ x: Math.random() })}>Change</button>
            <h1>searchQuery is {searchQuery}</h1>
            <h1>There are {filters.length} filters active.</h1>
            <div
                dangerouslySetInnerHTML={{ __html: searchQuery }}
            />
            <button
                onClick={() =>
                    setQuery(
                        { x: Math.random(), filters: [...filters, 'foo'], q: 'bar' },
                        'push'
                    )
                }
            >
                Change All
            </button>
        </div>
    );
};