.class public final enum Llyiahf/vczjk/i54;
.super Ljava/lang/Enum;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ss9;


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/i54;

.field public static final enum OooOOO0:Llyiahf/vczjk/i54;

.field public static final enum OooOOOO:Llyiahf/vczjk/i54;

.field public static final enum OooOOOo:Llyiahf/vczjk/i54;

.field public static final enum OooOOo:Llyiahf/vczjk/i54;

.field public static final enum OooOOo0:Llyiahf/vczjk/i54;

.field public static final enum OooOOoo:Llyiahf/vczjk/i54;

.field public static final enum OooOo:Llyiahf/vczjk/i54;

.field public static final enum OooOo0:Llyiahf/vczjk/i54;

.field public static final enum OooOo00:Llyiahf/vczjk/i54;

.field public static final enum OooOo0O:Llyiahf/vczjk/i54;

.field public static final enum OooOo0o:Llyiahf/vczjk/i54;

.field public static final enum OooOoO:Llyiahf/vczjk/i54;

.field public static final enum OooOoO0:Llyiahf/vczjk/i54;

.field public static final enum OooOoOO:Llyiahf/vczjk/i54;

.field public static final synthetic OooOoo0:[Llyiahf/vczjk/i54;


# instance fields
.field private final humanName:Ljava/lang/String;

.field private final mapValue:I

.field private final typeName:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 28

    new-instance v1, Llyiahf/vczjk/i54;

    const-string v0, "header_item"

    const-string v2, "TYPE_HEADER_ITEM"

    const/4 v3, 0x0

    invoke-direct {v1, v2, v3, v3, v0}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v1, Llyiahf/vczjk/i54;->OooOOO0:Llyiahf/vczjk/i54;

    new-instance v2, Llyiahf/vczjk/i54;

    const-string v0, "string_id_item"

    const-string v3, "TYPE_STRING_ID_ITEM"

    const/4 v4, 0x1

    invoke-direct {v2, v3, v4, v4, v0}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v2, Llyiahf/vczjk/i54;->OooOOO:Llyiahf/vczjk/i54;

    new-instance v3, Llyiahf/vczjk/i54;

    const-string v0, "type_id_item"

    const-string v4, "TYPE_TYPE_ID_ITEM"

    const/4 v5, 0x2

    invoke-direct {v3, v4, v5, v5, v0}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v3, Llyiahf/vczjk/i54;->OooOOOO:Llyiahf/vczjk/i54;

    new-instance v4, Llyiahf/vczjk/i54;

    const-string v0, "proto_id_item"

    const-string v5, "TYPE_PROTO_ID_ITEM"

    const/4 v6, 0x3

    invoke-direct {v4, v5, v6, v6, v0}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v4, Llyiahf/vczjk/i54;->OooOOOo:Llyiahf/vczjk/i54;

    new-instance v5, Llyiahf/vczjk/i54;

    const-string v0, "field_id_item"

    const-string v6, "TYPE_FIELD_ID_ITEM"

    const/4 v7, 0x4

    invoke-direct {v5, v6, v7, v7, v0}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v5, Llyiahf/vczjk/i54;->OooOOo0:Llyiahf/vczjk/i54;

    new-instance v6, Llyiahf/vczjk/i54;

    const-string v0, "method_id_item"

    const-string v7, "TYPE_METHOD_ID_ITEM"

    const/4 v8, 0x5

    invoke-direct {v6, v7, v8, v8, v0}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v6, Llyiahf/vczjk/i54;->OooOOo:Llyiahf/vczjk/i54;

    new-instance v7, Llyiahf/vczjk/i54;

    const-string v0, "class_def_item"

    const-string v8, "TYPE_CLASS_DEF_ITEM"

    const/4 v9, 0x6

    invoke-direct {v7, v8, v9, v9, v0}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v7, Llyiahf/vczjk/i54;->OooOOoo:Llyiahf/vczjk/i54;

    new-instance v8, Llyiahf/vczjk/i54;

    const-string v0, "call_site_id_item"

    const-string v9, "TYPE_CALL_SITE_ID_ITEM"

    const/4 v10, 0x7

    invoke-direct {v8, v9, v10, v10, v0}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    new-instance v9, Llyiahf/vczjk/i54;

    const-string v0, "method_handle_item"

    const-string v10, "TYPE_METHOD_HANDLE_ITEM"

    const/16 v11, 0x8

    invoke-direct {v9, v10, v11, v11, v0}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    new-instance v10, Llyiahf/vczjk/i54;

    const-string v0, "TYPE_MAP_LIST"

    const/16 v11, 0x9

    const/16 v12, 0x1000

    const-string v13, "map_list"

    invoke-direct {v10, v0, v11, v12, v13}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v10, Llyiahf/vczjk/i54;->OooOo00:Llyiahf/vczjk/i54;

    new-instance v11, Llyiahf/vczjk/i54;

    const-string v0, "TYPE_TYPE_LIST"

    const/16 v12, 0xa

    const/16 v13, 0x1001

    const-string v14, "type_list"

    invoke-direct {v11, v0, v12, v13, v14}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v11, Llyiahf/vczjk/i54;->OooOo0:Llyiahf/vczjk/i54;

    new-instance v12, Llyiahf/vczjk/i54;

    const-string v0, "TYPE_ANNOTATION_SET_REF_LIST"

    const/16 v13, 0xb

    const/16 v14, 0x1002

    const-string v15, "annotation_set_ref_list"

    invoke-direct {v12, v0, v13, v14, v15}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    new-instance v13, Llyiahf/vczjk/i54;

    const-string v0, "TYPE_ANNOTATION_SET_ITEM"

    const/16 v14, 0xc

    const/16 v15, 0x1003

    move-object/from16 v16, v1

    const-string v1, "annotation_set_item"

    invoke-direct {v13, v0, v14, v15, v1}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    new-instance v14, Llyiahf/vczjk/i54;

    const-string v0, "TYPE_CLASS_DATA_ITEM"

    const/16 v1, 0xd

    const/16 v15, 0x2000

    move-object/from16 v17, v2

    const-string v2, "class_data_item"

    invoke-direct {v14, v0, v1, v15, v2}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v14, Llyiahf/vczjk/i54;->OooOo0O:Llyiahf/vczjk/i54;

    new-instance v15, Llyiahf/vczjk/i54;

    const-string v0, "TYPE_CODE_ITEM"

    const/16 v1, 0xe

    const/16 v2, 0x2001

    move-object/from16 v18, v3

    const-string v3, "code_item"

    invoke-direct {v15, v0, v1, v2, v3}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v15, Llyiahf/vczjk/i54;->OooOo0o:Llyiahf/vczjk/i54;

    new-instance v0, Llyiahf/vczjk/i54;

    const-string v1, "TYPE_STRING_DATA_ITEM"

    const/16 v2, 0xf

    const/16 v3, 0x2002

    move-object/from16 v19, v4

    const-string v4, "string_data_item"

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/i54;->OooOo:Llyiahf/vczjk/i54;

    new-instance v1, Llyiahf/vczjk/i54;

    const-string v2, "TYPE_DEBUG_INFO_ITEM"

    const/16 v3, 0x10

    const/16 v4, 0x2003

    move-object/from16 v20, v0

    const-string v0, "debug_info_item"

    invoke-direct {v1, v2, v3, v4, v0}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/i54;

    const-string v2, "TYPE_ANNOTATION_ITEM"

    const/16 v3, 0x11

    const/16 v4, 0x2004

    move-object/from16 v21, v1

    const-string v1, "annotation_item"

    invoke-direct {v0, v2, v3, v4, v1}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/i54;

    const-string v2, "TYPE_ENCODED_ARRAY_ITEM"

    const/16 v3, 0x12

    const/16 v4, 0x2005

    move-object/from16 v22, v0

    const-string v0, "encoded_array_item"

    invoke-direct {v1, v2, v3, v4, v0}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v1, Llyiahf/vczjk/i54;->OooOoO0:Llyiahf/vczjk/i54;

    new-instance v0, Llyiahf/vczjk/i54;

    const-string v2, "TYPE_ANNOTATIONS_DIRECTORY_ITEM"

    const/16 v3, 0x13

    const/16 v4, 0x2006

    move-object/from16 v23, v1

    const-string v1, "annotations_directory_item"

    invoke-direct {v0, v2, v3, v4, v1}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/i54;->OooOoO:Llyiahf/vczjk/i54;

    new-instance v1, Llyiahf/vczjk/i54;

    const-string v2, "TYPE_MAP_ITEM"

    const/16 v3, 0x14

    const/4 v4, -0x1

    move-object/from16 v24, v0

    const-string v0, "map_item"

    invoke-direct {v1, v2, v3, v4, v0}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    sput-object v1, Llyiahf/vczjk/i54;->OooOoOO:Llyiahf/vczjk/i54;

    new-instance v0, Llyiahf/vczjk/i54;

    const-string v2, "type_item"

    const-string v3, "TYPE_TYPE_ITEM"

    move-object/from16 v25, v1

    const/16 v1, 0x15

    invoke-direct {v0, v3, v1, v4, v2}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/i54;

    const-string v2, "exception_handler_item"

    const-string v3, "TYPE_EXCEPTION_HANDLER_ITEM"

    move-object/from16 v26, v0

    const/16 v0, 0x16

    invoke-direct {v1, v3, v0, v4, v2}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/i54;

    const-string v2, "annotation_set_ref_item"

    const-string v3, "TYPE_ANNOTATION_SET_REF_ITEM"

    move-object/from16 v27, v1

    const/16 v1, 0x17

    invoke-direct {v0, v3, v1, v4, v2}, Llyiahf/vczjk/i54;-><init>(Ljava/lang/String;IILjava/lang/String;)V

    move-object/from16 v1, v16

    move-object/from16 v2, v17

    move-object/from16 v3, v18

    move-object/from16 v4, v19

    move-object/from16 v16, v20

    move-object/from16 v17, v21

    move-object/from16 v18, v22

    move-object/from16 v19, v23

    move-object/from16 v20, v24

    move-object/from16 v21, v25

    move-object/from16 v22, v26

    move-object/from16 v23, v27

    move-object/from16 v24, v0

    filled-new-array/range {v1 .. v24}, [Llyiahf/vczjk/i54;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/i54;->OooOoo0:[Llyiahf/vczjk/i54;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;IILjava/lang/String;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput p3, p0, Llyiahf/vczjk/i54;->mapValue:I

    iput-object p4, p0, Llyiahf/vczjk/i54;->typeName:Ljava/lang/String;

    const-string p1, "_item"

    invoke-virtual {p4, p1}, Ljava/lang/String;->endsWith(Ljava/lang/String;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x5

    const/4 p2, 0x0

    invoke-static {p1, p2, p4}, Llyiahf/vczjk/u81;->OooO0oO(IILjava/lang/String;)Ljava/lang/String;

    move-result-object p4

    :cond_0
    const/16 p1, 0x5f

    const/16 p2, 0x20

    invoke-virtual {p4, p1, p2}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/i54;->humanName:Ljava/lang/String;

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/i54;
    .locals 1

    const-class v0, Llyiahf/vczjk/i54;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/i54;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/i54;
    .locals 1

    sget-object v0, Llyiahf/vczjk/i54;->OooOoo0:[Llyiahf/vczjk/i54;

    invoke-virtual {v0}, [Llyiahf/vczjk/i54;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/i54;

    return-object v0
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/i54;->humanName:Ljava/lang/String;

    return-object v0
.end method

.method public final OooO0O0()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/i54;->mapValue:I

    return v0
.end method

.method public final OooO0Oo()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/i54;->typeName:Ljava/lang/String;

    return-object v0
.end method
