(function ($) {
    $(function(){

        var tables = {};
        $.fn.dataTableExt.oStdClasses.sPaging = ' pull-right ' + $.fn.dataTableExt.oStdClasses.sPaging;
        $.fn.dataTableExt.oStdClasses.sInfo = ' pull-left ' + $.fn.dataTableExt.oStdClasses.sInfo;

        $.each($('.result_table'), function(i,v){
            var tbl = $(this);
            var tbl_key = $(this).attr('id');
            if(tbl_key == undefined || tbl_key == '')
                return true;
            var colDef = [];
            $(this).find("thead th").each(function(index){
                var col = $(this);
                var searchable = false;
                if(col.data("isearch") === 1){
                    searchable = true;
                }
                colDef.push({
                    "searchable" : searchable, "targets" : index
                })
            });

            //change rendering for first (tlp) column in order to display the tlp color
            /*colDef.push({
             "render":  function ( data, type, row ) {
             return '<div class=\"' + data + '\"></div>';
             },
             "targets": 0
             })*/

            tables[tbl_key] = $(this).DataTable({
                //set pagingation length here, pagination_length is provided by the view rendering this page
                "pageLength" : pagination_length,
                "autoWidth": true,
                "columnDefs" : colDef,
                "searching": true,
                "processing": false,
                "serverSide": true,
                "stripeClasses": ["grp-row grp-row-odd", "grp-row grp-row-even"],
                "order": [[0,"asc"]],
                "search" : {"search" : initial_filter},
                "dom" : datatables_dom,
                "ajax": {
                    url: view_url,
                    type: 'POST',
                    data: {
                        "table_type": tbl_key,
                        "bulk_search_id" : bulk_search_id
                    },
                    dataSrc: function(data){
                        // Fill the selectors for filters
                        $.each($('tfoot select',tbl), function(i,v){
                            var options = data.cols[$(v).attr('id')];
                            if(options == undefined) return true;
                            $.each(options, function(i1,v1){
                                $.each(v1, function(i2,v2){
                                    $(v).append($('<option></option>').text(v2).attr('value', v1[v2]));
                                });
                            });
                            // bind the change event for filters
                            $(this).on('change', function(e){
                                var colidx = $(this).parents('tr').first().children().index($(this).parent());
                                tables[tbl_key].column(colidx).search($(this).val()).draw();
                            });
                        });

                        // Show total in headline
                        var hl_count = data.recordsTotal;
                        if(data.recordsFiltered != data.recordsTotal)
                            hl_count = data.recordsFiltered + ' of ' + hl_count;
                        $(tbl).parents('.result_box').first().find('.res_num').first().text('('+hl_count+')');

                        // get and display TLP color
                        if(data.draw_val === 1){
                            var tlp_map = data.tlp_map;
                        }

                        return data.data;
                    }
                },
                "createdRow": function ( row, data, index ) {
                    $.each( $('thead tr', this).find('.tbl_hide'), function(i,v){
                        $('td', row).eq($(this).index()).addClass('tbl_hide');
                    });

                    $('table').each(function(index){
                        $(this)
                    });
                },
                initComplete: function(settings, json) {
                    var pthis = this;
                    var s_cont = $('<div></div>').addClass('pull-right');
                    var s_inp = $('<input class="result_filter" type="text" placeholder="Filter">').val(initial_filter).keyup(function(){
                        var ithis = $(this);
                        window.clearTimeout($(this).data("timeout"));
                        $(this).data("timeout", setTimeout(function () {
                            pthis.fnFilter(ithis.get(0).value);
                        }, 500));
                    });
                    var rst = $('<button>Reset filter</button>').button({
                        icons: {
                            primary: 'ui-icon-close'
                        },
                        text: false
                    }).addClass('dt_filter_rst').click(function(){
                        $(this).prev('input').val('').trigger('keyup');
                    });
                    var li = $('<span class="ui-icon ui-icon-clock tbl_processing pull-left" style="margin-top: 4px;display:none;"></span>');

                    s_cont.append(li);
                    s_cont.append(s_inp);
                    s_cont.append(rst);

                    $(this).parents('.result_box').first().find('.result_head').first().prepend(s_cont);

                },
                "drawCallback": function(settings){
                    $(this).parents('.result_box').first().find('.paginate_button').button();
                }
            }).on( 'processing.dt', function ( e, settings, processing ) {
                var tpi = $(this).parents('.result_box').first().find('.tbl_processing').first();
                tpi.css( 'display', processing ? 'block' : 'none' );
            } );
        });

        // Make the search input in the headline search the tables
        var oi_tmp = initial_filter;
        var si = $('input[name="search_term"]').first();
        si.val(initial_filter).on('keyup', function(){
            var ni = $(this).val();
            if(oi_tmp!=ni){
                oi_tmp = ni;
                $('.result_filter').val(ni).trigger('keyup');
            }
        }).on('keypress', function(e){
            if(initial_filter != ''){
                if((e.keyCode || e.which || e.charCode)==13)
                    return false;
            }
        });

        // Initilize the column filters
        // enable filter on every column (within every table on this page) if there is an '<input>' field in this column's footer
        $.each(tables, function(table_id, table) {
            table.columns().every(function() {
                var that = this;
                $('input',this.footer()).on('keyup change', function() {
                    that.search(this.value)
                        .draw();
                });
            });
        });
    });
}(django.jQuery));
