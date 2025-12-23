.class public enum Llyiahf/vczjk/vpa;
.super Ljava/lang/Enum;
.source "SourceFile"


# static fields
.field public static final enum OooOOO:Llyiahf/vczjk/ppa;

.field public static final enum OooOOO0:Llyiahf/vczjk/npa;

.field public static final enum OooOOOO:Llyiahf/vczjk/rpa;

.field public static final synthetic OooOOOo:[Llyiahf/vczjk/vpa;


# instance fields
.field private final javaType:Llyiahf/vczjk/xpa;

.field private final wireType:I


# direct methods
.method static constructor <clinit>()V
    .locals 39

    const/16 v9, 0x8

    new-instance v10, Llyiahf/vczjk/vpa;

    sget-object v11, Llyiahf/vczjk/xpa;->OooOOOo:Llyiahf/vczjk/xpa;

    const-string v12, "DOUBLE"

    const/4 v13, 0x0

    const/4 v14, 0x1

    invoke-direct {v10, v12, v13, v11, v14}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    new-instance v11, Llyiahf/vczjk/vpa;

    sget-object v12, Llyiahf/vczjk/xpa;->OooOOOO:Llyiahf/vczjk/xpa;

    const-string v15, "FLOAT"

    const/4 v0, 0x5

    invoke-direct {v11, v15, v14, v12, v0}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    new-instance v12, Llyiahf/vczjk/vpa;

    sget-object v15, Llyiahf/vczjk/xpa;->OooOOO:Llyiahf/vczjk/xpa;

    const-string v1, "INT64"

    const/4 v2, 0x2

    invoke-direct {v12, v1, v2, v15, v13}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    new-instance v1, Llyiahf/vczjk/vpa;

    const-string v3, "UINT64"

    const/4 v4, 0x3

    invoke-direct {v1, v3, v4, v15, v13}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    new-instance v3, Llyiahf/vczjk/vpa;

    sget-object v5, Llyiahf/vczjk/xpa;->OooOOO0:Llyiahf/vczjk/xpa;

    const-string v6, "INT32"

    const/4 v7, 0x4

    invoke-direct {v3, v6, v7, v5, v13}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    new-instance v6, Llyiahf/vczjk/vpa;

    move/from16 v24, v7

    const-string v7, "FIXED64"

    invoke-direct {v6, v7, v0, v15, v14}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    new-instance v7, Llyiahf/vczjk/vpa;

    const/4 v14, 0x6

    const-string v4, "FIXED32"

    invoke-direct {v7, v4, v14, v5, v0}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    new-instance v4, Llyiahf/vczjk/vpa;

    move/from16 v27, v14

    sget-object v14, Llyiahf/vczjk/xpa;->OooOOo0:Llyiahf/vczjk/xpa;

    const-string v0, "BOOL"

    const/4 v8, 0x7

    invoke-direct {v4, v0, v8, v14, v13}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    new-instance v0, Llyiahf/vczjk/npa;

    sget-object v14, Llyiahf/vczjk/xpa;->OooOOo:Llyiahf/vczjk/xpa;

    move/from16 v30, v8

    const-string v8, "STRING"

    invoke-direct {v0, v8, v9, v14, v2}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    sput-object v0, Llyiahf/vczjk/vpa;->OooOOO0:Llyiahf/vczjk/npa;

    new-instance v8, Llyiahf/vczjk/ppa;

    sget-object v14, Llyiahf/vczjk/xpa;->OooOo0:Llyiahf/vczjk/xpa;

    move/from16 v31, v9

    const-string v9, "GROUP"

    const/16 v2, 0x9

    const/4 v13, 0x3

    invoke-direct {v8, v9, v2, v14, v13}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    sput-object v8, Llyiahf/vczjk/vpa;->OooOOO:Llyiahf/vczjk/ppa;

    new-instance v2, Llyiahf/vczjk/rpa;

    const-string v9, "MESSAGE"

    move-object/from16 v34, v0

    const/16 v0, 0xa

    const/4 v13, 0x2

    invoke-direct {v2, v9, v0, v14, v13}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    sput-object v2, Llyiahf/vczjk/vpa;->OooOOOO:Llyiahf/vczjk/rpa;

    new-instance v0, Llyiahf/vczjk/tpa;

    sget-object v9, Llyiahf/vczjk/xpa;->OooOOoo:Llyiahf/vczjk/xpa;

    const-string v14, "BYTES"

    move-object/from16 v35, v1

    const/16 v1, 0xb

    invoke-direct {v0, v14, v1, v9, v13}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    new-instance v1, Llyiahf/vczjk/vpa;

    const-string v9, "UINT32"

    const/4 v13, 0x0

    const/16 v14, 0xc

    invoke-direct {v1, v9, v14, v5, v13}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    new-instance v9, Llyiahf/vczjk/vpa;

    sget-object v14, Llyiahf/vczjk/xpa;->OooOo00:Llyiahf/vczjk/xpa;

    move-object/from16 v32, v0

    const-string v0, "ENUM"

    move-object/from16 v36, v1

    const/16 v1, 0xd

    invoke-direct {v9, v0, v1, v14, v13}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    new-instance v0, Llyiahf/vczjk/vpa;

    const-string v1, "SFIXED32"

    const/16 v13, 0xe

    const/4 v14, 0x5

    invoke-direct {v0, v1, v13, v5, v14}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    new-instance v1, Llyiahf/vczjk/vpa;

    const-string v13, "SFIXED64"

    move-object/from16 v25, v0

    const/16 v0, 0xf

    const/4 v14, 0x1

    invoke-direct {v1, v13, v0, v15, v14}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    new-instance v0, Llyiahf/vczjk/vpa;

    const-string v13, "SINT32"

    move-object/from16 v37, v1

    move/from16 v38, v14

    const/16 v1, 0x10

    const/4 v14, 0x0

    invoke-direct {v0, v13, v1, v5, v14}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    new-instance v1, Llyiahf/vczjk/vpa;

    const-string v5, "SINT64"

    const/16 v13, 0x11

    invoke-direct {v1, v5, v13, v15, v14}, Llyiahf/vczjk/vpa;-><init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V

    const/16 v5, 0x12

    new-array v5, v5, [Llyiahf/vczjk/vpa;

    aput-object v10, v5, v14

    aput-object v11, v5, v38

    const/16 v33, 0x2

    aput-object v12, v5, v33

    const/16 v26, 0x3

    aput-object v35, v5, v26

    aput-object v3, v5, v24

    const/16 v28, 0x5

    aput-object v6, v5, v28

    aput-object v7, v5, v27

    aput-object v4, v5, v30

    aput-object v34, v5, v31

    const/16 v29, 0x9

    aput-object v8, v5, v29

    const/16 v23, 0xa

    aput-object v2, v5, v23

    const/16 v22, 0xb

    aput-object v32, v5, v22

    const/16 v21, 0xc

    aput-object v36, v5, v21

    const/16 v20, 0xd

    aput-object v9, v5, v20

    const/16 v19, 0xe

    aput-object v25, v5, v19

    const/16 v18, 0xf

    aput-object v37, v5, v18

    const/16 v17, 0x10

    aput-object v0, v5, v17

    const/16 v16, 0x11

    aput-object v1, v5, v16

    sput-object v5, Llyiahf/vczjk/vpa;->OooOOOo:[Llyiahf/vczjk/vpa;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILlyiahf/vczjk/xpa;I)V
    .locals 0

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    iput-object p3, p0, Llyiahf/vczjk/vpa;->javaType:Llyiahf/vczjk/xpa;

    iput p4, p0, Llyiahf/vczjk/vpa;->wireType:I

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Llyiahf/vczjk/vpa;
    .locals 1

    const-class v0, Llyiahf/vczjk/vpa;

    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/vpa;

    return-object p0
.end method

.method public static values()[Llyiahf/vczjk/vpa;
    .locals 1

    sget-object v0, Llyiahf/vczjk/vpa;->OooOOOo:[Llyiahf/vczjk/vpa;

    invoke-virtual {v0}, [Llyiahf/vczjk/vpa;->clone()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Llyiahf/vczjk/vpa;

    return-object v0
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/xpa;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vpa;->javaType:Llyiahf/vczjk/xpa;

    return-object v0
.end method

.method public final OooO0O0()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/vpa;->wireType:I

    return v0
.end method
