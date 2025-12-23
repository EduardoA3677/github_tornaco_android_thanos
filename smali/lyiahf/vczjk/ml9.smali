.class public final synthetic Llyiahf/vczjk/ml9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nl9;
.implements Llyiahf/vczjk/sl9;
.implements Lorg/apache/commons/io/function/IOFunction;
.implements Lorg/apache/commons/io/output/AbstractByteArrayOutputStream$InputStreamConstructor;
.implements Llyiahf/vczjk/jka;
.implements Llyiahf/vczjk/jf3;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/ml9;

.field public static final OooOOOO:Llyiahf/vczjk/ml9;

.field public static final OooOOOo:Llyiahf/vczjk/ml9;

.field public static final OooOOo:Llyiahf/vczjk/ml9;

.field public static final OooOOo0:Llyiahf/vczjk/ml9;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/ml9;

    const/4 v1, 0x4

    invoke-direct {v0, v1}, Llyiahf/vczjk/ml9;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/ml9;->OooOOO:Llyiahf/vczjk/ml9;

    new-instance v0, Llyiahf/vczjk/ml9;

    const/4 v1, 0x5

    invoke-direct {v0, v1}, Llyiahf/vczjk/ml9;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/ml9;->OooOOOO:Llyiahf/vczjk/ml9;

    new-instance v0, Llyiahf/vczjk/ml9;

    const/4 v1, 0x6

    invoke-direct {v0, v1}, Llyiahf/vczjk/ml9;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/ml9;->OooOOOo:Llyiahf/vczjk/ml9;

    new-instance v0, Llyiahf/vczjk/ml9;

    const/4 v1, 0x7

    invoke-direct {v0, v1}, Llyiahf/vczjk/ml9;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/ml9;->OooOOo0:Llyiahf/vczjk/ml9;

    new-instance v0, Llyiahf/vczjk/ml9;

    const/16 v1, 0x8

    invoke-direct {v0, v1}, Llyiahf/vczjk/ml9;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/ml9;->OooOOo:Llyiahf/vczjk/ml9;

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/ml9;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public OooO00o(Llyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;)Z
    .locals 2

    iget v0, p0, Llyiahf/vczjk/ml9;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    invoke-virtual {p1}, Llyiahf/vczjk/wj7;->OooO0O0()J

    move-result-wide v0

    invoke-virtual {p2, v0, v1}, Llyiahf/vczjk/wj7;->OooO00o(J)Z

    move-result p1

    return p1

    :pswitch_0
    invoke-virtual {p1, p2}, Llyiahf/vczjk/wj7;->OooO0oO(Llyiahf/vczjk/wj7;)Z

    move-result p1

    return p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 32

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/ml9;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Ljava/util/List;

    if-eqz v1, :cond_6

    new-instance v3, Ljava/util/ArrayList;

    const/16 v4, 0xa

    invoke-static {v1, v4}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_5

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/zqa;

    iget-object v5, v4, Llyiahf/vczjk/zqa;->OooOOo0:Ljava/util/ArrayList;

    invoke-interface {v5}, Ljava/util/Collection;->isEmpty()Z

    move-result v6

    const/4 v7, 0x0

    if-nez v6, :cond_0

    invoke-interface {v5, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/mw1;

    :goto_1
    move-object v13, v5

    goto :goto_2

    :cond_0
    sget-object v5, Llyiahf/vczjk/mw1;->OooO0O0:Llyiahf/vczjk/mw1;

    goto :goto_1

    :goto_2
    new-instance v8, Llyiahf/vczjk/mqa;

    iget-object v5, v4, Llyiahf/vczjk/zqa;->OooO00o:Ljava/lang/String;

    invoke-static {v5}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    move-result-object v9

    const-string v5, "fromString(id)"

    invoke-static {v9, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v11, Ljava/util/HashSet;

    iget-object v5, v4, Llyiahf/vczjk/zqa;->OooOOOo:Ljava/util/ArrayList;

    invoke-direct {v11, v5}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    iget-wide v5, v4, Llyiahf/vczjk/zqa;->OooO0o0:J

    const-wide/16 v14, 0x0

    cmp-long v10, v5, v14

    if-eqz v10, :cond_1

    new-instance v12, Llyiahf/vczjk/kqa;

    iget-wide v14, v4, Llyiahf/vczjk/zqa;->OooO0o:J

    invoke-direct {v12, v5, v6, v14, v15}, Llyiahf/vczjk/kqa;-><init>(JJ)V

    goto :goto_3

    :cond_1
    const/4 v12, 0x0

    :goto_3
    sget-object v14, Llyiahf/vczjk/lqa;->OooOOO0:Llyiahf/vczjk/lqa;

    iget v15, v4, Llyiahf/vczjk/zqa;->OooO0oo:I

    move-object/from16 v31, v8

    iget-wide v7, v4, Llyiahf/vczjk/zqa;->OooO0Oo:J

    iget-object v2, v4, Llyiahf/vczjk/zqa;->OooO0O0:Llyiahf/vczjk/lqa;

    if-ne v2, v14, :cond_4

    sget-object v16, Llyiahf/vczjk/ara;->OooOoO0:Ljava/lang/String;

    const/16 v16, 0x1

    if-ne v2, v14, :cond_2

    if-lez v15, :cond_2

    move/from16 v14, v16

    goto :goto_4

    :cond_2
    const/4 v14, 0x0

    :goto_4
    if-eqz v10, :cond_3

    move/from16 v22, v16

    goto :goto_5

    :cond_3
    const/16 v22, 0x0

    :goto_5
    iget v2, v4, Llyiahf/vczjk/zqa;->OooO:I

    move-object/from16 p1, v1

    iget-wide v0, v4, Llyiahf/vczjk/zqa;->OooOO0:J

    move-wide/from16 v17, v0

    iget-wide v0, v4, Llyiahf/vczjk/zqa;->OooOO0O:J

    iget v10, v4, Llyiahf/vczjk/zqa;->OooOO0o:I

    move-wide/from16 v19, v0

    iget-wide v0, v4, Llyiahf/vczjk/zqa;->OooO0o:J

    move-wide/from16 v25, v0

    iget-wide v0, v4, Llyiahf/vczjk/zqa;->OooOOO:J

    move-wide/from16 v29, v0

    move/from16 v16, v2

    move-wide/from16 v27, v5

    move-wide/from16 v23, v7

    move/from16 v21, v10

    invoke-static/range {v14 .. v30}, Llyiahf/vczjk/tp6;->OooOO0O(ZIIJJIZJJJJ)J

    move-result-wide v0

    move v14, v15

    move-wide/from16 v17, v23

    :goto_6
    move-wide/from16 v20, v0

    goto :goto_7

    :cond_4
    move-object/from16 p1, v1

    move-wide/from16 v17, v7

    move v14, v15

    const-wide v0, 0x7fffffffffffffffL

    goto :goto_6

    :goto_7
    iget-object v0, v4, Llyiahf/vczjk/zqa;->OooO0oO:Llyiahf/vczjk/qk1;

    move-object/from16 v19, v12

    iget-object v12, v4, Llyiahf/vczjk/zqa;->OooO0OO:Llyiahf/vczjk/mw1;

    iget v1, v4, Llyiahf/vczjk/zqa;->OooOOOO:I

    iget-object v10, v4, Llyiahf/vczjk/zqa;->OooO0O0:Llyiahf/vczjk/lqa;

    iget v15, v4, Llyiahf/vczjk/zqa;->OooOOO0:I

    move-object/from16 v16, v0

    move/from16 v22, v1

    move-object/from16 v8, v31

    invoke-direct/range {v8 .. v22}, Llyiahf/vczjk/mqa;-><init>(Ljava/util/UUID;Llyiahf/vczjk/lqa;Ljava/util/HashSet;Llyiahf/vczjk/mw1;Llyiahf/vczjk/mw1;IILlyiahf/vczjk/qk1;JLlyiahf/vczjk/kqa;JI)V

    invoke-virtual {v3, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    goto/16 :goto_0

    :cond_5
    move-object v2, v3

    goto :goto_8

    :cond_6
    const/4 v2, 0x0

    :goto_8
    return-object v2

    :pswitch_0
    move-object/from16 v0, p1

    check-cast v0, Lorg/apache/commons/io/output/ThresholdingOutputStream;

    invoke-static {v0}, Lorg/apache/commons/io/output/ThresholdingOutputStream;->OooO0Oo(Lorg/apache/commons/io/output/ThresholdingOutputStream;)Ljava/io/OutputStream;

    move-result-object v0

    return-object v0

    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method

.method public construct([BII)Ljava/io/InputStream;
    .locals 0

    invoke-static {p2, p1, p3}, Lorg/apache/commons/io/output/UnsynchronizedByteArrayOutputStream;->OooO0Oo(I[BI)Lorg/apache/commons/io/input/UnsynchronizedByteArrayInputStream;

    move-result-object p1

    return-object p1
.end method
