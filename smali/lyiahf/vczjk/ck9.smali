.class public final Llyiahf/vczjk/ck9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/mk9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mk9;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ck9;->this$0:Llyiahf/vczjk/mk9;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/ck9;

    iget-object v0, p0, Llyiahf/vczjk/ck9;->this$0:Llyiahf/vczjk/mk9;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/ck9;-><init>(Llyiahf/vczjk/mk9;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ck9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ck9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ck9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 49

    move-object/from16 v0, p0

    const/4 v1, 0x2

    const/4 v2, 0x1

    sget-object v3, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v4, v0, Llyiahf/vczjk/ck9;->label:I

    sget-object v5, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz v4, :cond_1

    if-ne v4, v2, :cond_0

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v7, p1

    goto :goto_1

    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v4, v0, Llyiahf/vczjk/ck9;->this$0:Llyiahf/vczjk/mk9;

    iget-object v4, v4, Llyiahf/vczjk/mk9;->OooO0oo:Llyiahf/vczjk/c01;

    if-eqz v4, :cond_2d

    iput v2, v0, Llyiahf/vczjk/ck9;->label:I

    check-cast v4, Llyiahf/vczjk/v9;

    iget-object v4, v4, Llyiahf/vczjk/v9;->OooO00o:Llyiahf/vczjk/w9;

    iget-object v4, v4, Llyiahf/vczjk/w9;->OooO00o:Landroid/content/ClipboardManager;

    invoke-virtual {v4}, Landroid/content/ClipboardManager;->getPrimaryClip()Landroid/content/ClipData;

    move-result-object v4

    if-eqz v4, :cond_2

    new-instance v7, Llyiahf/vczjk/a01;

    invoke-direct {v7, v4}, Llyiahf/vczjk/a01;-><init>(Landroid/content/ClipData;)V

    goto :goto_0

    :cond_2
    const/4 v7, 0x0

    :goto_0
    if-ne v7, v3, :cond_3

    return-object v3

    :cond_3
    :goto_1
    check-cast v7, Llyiahf/vczjk/a01;

    if-eqz v7, :cond_2d

    iget-object v3, v7, Llyiahf/vczjk/a01;->OooO00o:Landroid/content/ClipData;

    const/4 v4, 0x0

    invoke-virtual {v3, v4}, Landroid/content/ClipData;->getItemAt(I)Landroid/content/ClipData$Item;

    move-result-object v3

    if-eqz v3, :cond_2b

    invoke-virtual {v3}, Landroid/content/ClipData$Item;->getText()Ljava/lang/CharSequence;

    move-result-object v3

    if-eqz v3, :cond_2b

    instance-of v7, v3, Landroid/text/Spanned;

    if-nez v7, :cond_4

    new-instance v6, Llyiahf/vczjk/an;

    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v6, v1}, Llyiahf/vczjk/an;-><init>(Ljava/lang/String;)V

    move-object/from16 v40, v5

    goto/16 :goto_15

    :cond_4
    move-object v7, v3

    check-cast v7, Landroid/text/Spanned;

    invoke-interface {v3}, Ljava/lang/CharSequence;->length()I

    move-result v8

    const-class v9, Landroid/text/Annotation;

    invoke-interface {v7, v4, v8, v9}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    move-result-object v8

    check-cast v8, [Landroid/text/Annotation;

    new-instance v9, Ljava/util/ArrayList;

    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    invoke-static {v8}, Llyiahf/vczjk/sy;->o000000o([Ljava/lang/Object;)I

    move-result v10

    if-ltz v10, :cond_28

    move v11, v4

    :goto_2
    aget-object v12, v8, v11

    invoke-virtual {v12}, Landroid/text/Annotation;->getKey()Ljava/lang/String;

    move-result-object v13

    const-string v14, "androidx.compose.text.SpanStyle"

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v13

    if-nez v13, :cond_5

    move/from16 v42, v1

    move/from16 p1, v4

    move-object/from16 v40, v5

    goto/16 :goto_13

    :cond_5
    invoke-interface {v7, v12}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    move-result v13

    invoke-interface {v7, v12}, Landroid/text/Spanned;->getSpanEnd(Ljava/lang/Object;)I

    move-result v14

    invoke-virtual {v12}, Landroid/text/Annotation;->getValue()Ljava/lang/String;

    move-result-object v12

    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    move-result-object v15

    invoke-static {v12, v4}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object v12

    array-length v6, v12

    invoke-virtual {v15, v12, v4, v6}, Landroid/os/Parcel;->unmarshall([BII)V

    invoke-virtual {v15, v4}, Landroid/os/Parcel;->setDataPosition(I)V

    sget-wide v16, Llyiahf/vczjk/n21;->OooOO0:J

    sget-wide v18, Llyiahf/vczjk/un9;->OooO0OO:J

    move-wide/from16 v21, v16

    move-wide/from16 v35, v21

    move-wide/from16 v23, v18

    move-wide/from16 v30, v23

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v29, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v37, 0x0

    const/16 v38, 0x0

    :goto_3
    invoke-virtual {v15}, Landroid/os/Parcel;->dataAvail()I

    move-result v6

    if-le v6, v2, :cond_6

    invoke-virtual {v15}, Landroid/os/Parcel;->readByte()B

    move-result v6

    const/16 v12, 0x8

    if-ne v6, v2, :cond_7

    invoke-virtual {v15}, Landroid/os/Parcel;->dataAvail()I

    move-result v6

    if-lt v6, v12, :cond_6

    invoke-virtual {v15}, Landroid/os/Parcel;->readLong()J

    move-result-wide v21

    sget v6, Llyiahf/vczjk/n21;->OooOO0O:I

    goto :goto_3

    :cond_6
    move/from16 v42, v1

    move/from16 p1, v4

    move-object/from16 v40, v5

    goto/16 :goto_12

    :cond_7
    const-wide v16, 0x200000000L

    const-wide v18, 0x100000000L

    move/from16 p1, v4

    move-object/from16 v40, v5

    const-wide/16 v4, 0x0

    const/4 v12, 0x5

    if-ne v6, v1, :cond_c

    invoke-virtual {v15}, Landroid/os/Parcel;->dataAvail()I

    move-result v6

    if-lt v6, v12, :cond_b

    invoke-virtual {v15}, Landroid/os/Parcel;->readByte()B

    move-result v6

    if-ne v6, v2, :cond_8

    move-wide/from16 v1, v18

    goto :goto_4

    :cond_8
    if-ne v6, v1, :cond_9

    move-wide/from16 v1, v16

    goto :goto_4

    :cond_9
    move-wide v1, v4

    :goto_4
    invoke-static {v1, v2, v4, v5}, Llyiahf/vczjk/vn9;->OooO00o(JJ)Z

    move-result v4

    if-eqz v4, :cond_a

    sget-wide v1, Llyiahf/vczjk/un9;->OooO0OO:J

    :goto_5
    move-wide/from16 v23, v1

    goto :goto_6

    :cond_a
    invoke-virtual {v15}, Landroid/os/Parcel;->readFloat()F

    move-result v4

    invoke-static {v4, v1, v2}, Llyiahf/vczjk/eo6;->OooOo0(FJ)J

    move-result-wide v1

    goto :goto_5

    :goto_6
    move/from16 v4, p1

    :goto_7
    move-object/from16 v5, v40

    const/4 v1, 0x2

    :goto_8
    const/4 v2, 0x1

    goto :goto_3

    :cond_b
    move/from16 v42, v1

    goto/16 :goto_12

    :cond_c
    const/4 v1, 0x3

    const/4 v2, 0x4

    if-ne v6, v1, :cond_e

    invoke-virtual {v15}, Landroid/os/Parcel;->dataAvail()I

    move-result v1

    if-lt v1, v2, :cond_d

    new-instance v1, Llyiahf/vczjk/ib3;

    invoke-virtual {v15}, Landroid/os/Parcel;->readInt()I

    move-result v2

    invoke-direct {v1, v2}, Llyiahf/vczjk/ib3;-><init>(I)V

    move/from16 v4, p1

    move-object/from16 v25, v1

    goto :goto_7

    :cond_d
    const/16 v42, 0x2

    goto/16 :goto_12

    :cond_e
    if-ne v6, v2, :cond_11

    invoke-virtual {v15}, Landroid/os/Parcel;->dataAvail()I

    move-result v1

    const/4 v2, 0x1

    if-lt v1, v2, :cond_d

    invoke-virtual {v15}, Landroid/os/Parcel;->readByte()B

    move-result v1

    if-nez v1, :cond_10

    :cond_f
    move/from16 v1, p1

    goto :goto_9

    :cond_10
    if-ne v1, v2, :cond_f

    move v1, v2

    :goto_9
    new-instance v4, Llyiahf/vczjk/cb3;

    invoke-direct {v4, v1}, Llyiahf/vczjk/cb3;-><init>(I)V

    move-object/from16 v26, v4

    move-object/from16 v5, v40

    const/4 v1, 0x2

    move/from16 v4, p1

    goto/16 :goto_3

    :cond_11
    const/4 v2, 0x1

    if-ne v6, v12, :cond_16

    invoke-virtual {v15}, Landroid/os/Parcel;->dataAvail()I

    move-result v4

    if-lt v4, v2, :cond_d

    invoke-virtual {v15}, Landroid/os/Parcel;->readByte()B

    move-result v4

    if-nez v4, :cond_13

    :cond_12
    move/from16 v1, p1

    goto :goto_a

    :cond_13
    if-ne v4, v2, :cond_14

    const v1, 0xffff

    goto :goto_a

    :cond_14
    if-ne v4, v1, :cond_15

    const/4 v1, 0x2

    goto :goto_a

    :cond_15
    const/4 v1, 0x2

    if-ne v4, v1, :cond_12

    const/4 v1, 0x1

    :goto_a
    new-instance v2, Llyiahf/vczjk/db3;

    invoke-direct {v2, v1}, Llyiahf/vczjk/db3;-><init>(I)V

    move/from16 v4, p1

    move-object/from16 v27, v2

    goto :goto_7

    :cond_16
    const/4 v1, 0x6

    if-ne v6, v1, :cond_17

    invoke-virtual {v15}, Landroid/os/Parcel;->readString()Ljava/lang/String;

    move-result-object v29

    goto :goto_6

    :cond_17
    const/4 v1, 0x7

    if-ne v6, v1, :cond_1b

    invoke-virtual {v15}, Landroid/os/Parcel;->dataAvail()I

    move-result v1

    if-lt v1, v12, :cond_d

    invoke-virtual {v15}, Landroid/os/Parcel;->readByte()B

    move-result v1

    const/4 v2, 0x1

    if-ne v1, v2, :cond_18

    move-wide/from16 v1, v18

    goto :goto_b

    :cond_18
    const/4 v2, 0x2

    if-ne v1, v2, :cond_19

    move-wide/from16 v1, v16

    goto :goto_b

    :cond_19
    move-wide v1, v4

    :goto_b
    invoke-static {v1, v2, v4, v5}, Llyiahf/vczjk/vn9;->OooO00o(JJ)Z

    move-result v4

    if-eqz v4, :cond_1a

    sget-wide v1, Llyiahf/vczjk/un9;->OooO0OO:J

    :goto_c
    move-wide/from16 v30, v1

    goto/16 :goto_6

    :cond_1a
    invoke-virtual {v15}, Landroid/os/Parcel;->readFloat()F

    move-result v4

    invoke-static {v4, v1, v2}, Llyiahf/vczjk/eo6;->OooOo0(FJ)J

    move-result-wide v1

    goto :goto_c

    :cond_1b
    const/16 v1, 0x8

    if-ne v6, v1, :cond_1c

    invoke-virtual {v15}, Landroid/os/Parcel;->dataAvail()I

    move-result v1

    const/4 v2, 0x4

    if-lt v1, v2, :cond_d

    invoke-virtual {v15}, Landroid/os/Parcel;->readFloat()F

    move-result v1

    new-instance v2, Llyiahf/vczjk/f90;

    invoke-direct {v2, v1}, Llyiahf/vczjk/f90;-><init>(F)V

    move/from16 v4, p1

    move-object/from16 v32, v2

    goto/16 :goto_7

    :cond_1c
    const/16 v1, 0x9

    if-ne v6, v1, :cond_1d

    invoke-virtual {v15}, Landroid/os/Parcel;->dataAvail()I

    move-result v1

    const/16 v2, 0x8

    if-lt v1, v2, :cond_d

    new-instance v1, Llyiahf/vczjk/ll9;

    invoke-virtual {v15}, Landroid/os/Parcel;->readFloat()F

    move-result v2

    invoke-virtual {v15}, Landroid/os/Parcel;->readFloat()F

    move-result v4

    invoke-direct {v1, v2, v4}, Llyiahf/vczjk/ll9;-><init>(FF)V

    move/from16 v4, p1

    move-object/from16 v33, v1

    goto/16 :goto_7

    :cond_1d
    const/16 v1, 0xa

    if-ne v6, v1, :cond_1e

    invoke-virtual {v15}, Landroid/os/Parcel;->dataAvail()I

    move-result v1

    const/16 v2, 0x8

    if-lt v1, v2, :cond_d

    invoke-virtual {v15}, Landroid/os/Parcel;->readLong()J

    move-result-wide v35

    sget v1, Llyiahf/vczjk/n21;->OooOO0O:I

    goto/16 :goto_6

    :cond_1e
    const/16 v1, 0xb

    if-ne v6, v1, :cond_26

    invoke-virtual {v15}, Landroid/os/Parcel;->dataAvail()I

    move-result v1

    const/4 v2, 0x4

    if-lt v1, v2, :cond_d

    invoke-virtual {v15}, Landroid/os/Parcel;->readInt()I

    move-result v1

    const/16 v42, 0x2

    and-int/lit8 v2, v1, 0x2

    if-eqz v2, :cond_1f

    const/4 v2, 0x1

    :goto_d
    const/16 v41, 0x1

    goto :goto_e

    :cond_1f
    move/from16 v2, p1

    goto :goto_d

    :goto_e
    and-int/lit8 v1, v1, 0x1

    if-eqz v1, :cond_20

    const/4 v1, 0x1

    goto :goto_f

    :cond_20
    move/from16 v1, p1

    :goto_f
    sget-object v4, Llyiahf/vczjk/vh9;->OooO0Oo:Llyiahf/vczjk/vh9;

    sget-object v5, Llyiahf/vczjk/vh9;->OooO0OO:Llyiahf/vczjk/vh9;

    if-eqz v2, :cond_22

    if-eqz v1, :cond_22

    filled-new-array {v4, v5}, [Llyiahf/vczjk/vh9;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    invoke-static/range {p1 .. p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v4

    move/from16 v5, p1

    :goto_10
    if-ge v5, v4, :cond_21

    invoke-interface {v1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/vh9;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    iget v6, v6, Llyiahf/vczjk/vh9;->OooO00o:I

    or-int/2addr v2, v6

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    const/16 v41, 0x1

    add-int/lit8 v5, v5, 0x1

    goto :goto_10

    :cond_21
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v1

    new-instance v2, Llyiahf/vczjk/vh9;

    invoke-direct {v2, v1}, Llyiahf/vczjk/vh9;-><init>(I)V

    move-object/from16 v37, v2

    goto :goto_11

    :cond_22
    if-eqz v2, :cond_23

    move-object/from16 v37, v4

    goto :goto_11

    :cond_23
    if-eqz v1, :cond_24

    move-object/from16 v37, v5

    goto :goto_11

    :cond_24
    sget-object v1, Llyiahf/vczjk/vh9;->OooO0O0:Llyiahf/vczjk/vh9;

    move-object/from16 v37, v1

    :cond_25
    :goto_11
    move/from16 v4, p1

    move-object/from16 v5, v40

    move/from16 v1, v42

    goto/16 :goto_8

    :cond_26
    const/16 v42, 0x2

    const/16 v1, 0xc

    if-ne v6, v1, :cond_25

    invoke-virtual {v15}, Landroid/os/Parcel;->dataAvail()I

    move-result v1

    const/16 v2, 0x14

    if-lt v1, v2, :cond_27

    new-instance v43, Llyiahf/vczjk/ij8;

    invoke-virtual {v15}, Landroid/os/Parcel;->readLong()J

    move-result-wide v44

    sget v1, Llyiahf/vczjk/n21;->OooOO0O:I

    invoke-virtual {v15}, Landroid/os/Parcel;->readFloat()F

    move-result v1

    invoke-virtual {v15}, Landroid/os/Parcel;->readFloat()F

    move-result v2

    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v4, v1

    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v1, v1

    const/16 v6, 0x20

    shl-long/2addr v4, v6

    const-wide v16, 0xffffffffL

    and-long v1, v1, v16

    or-long v46, v4, v1

    invoke-virtual {v15}, Landroid/os/Parcel;->readFloat()F

    move-result v48

    invoke-direct/range {v43 .. v48}, Llyiahf/vczjk/ij8;-><init>(JJF)V

    move/from16 v4, p1

    move-object/from16 v5, v40

    move/from16 v1, v42

    move-object/from16 v38, v43

    goto/16 :goto_8

    :cond_27
    :goto_12
    new-instance v20, Llyiahf/vczjk/dy8;

    const/16 v34, 0x0

    const v39, 0xc000

    const/16 v28, 0x0

    invoke-direct/range {v20 .. v39}, Llyiahf/vczjk/dy8;-><init>(JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/db3;Llyiahf/vczjk/ba3;Ljava/lang/String;JLlyiahf/vczjk/f90;Llyiahf/vczjk/ll9;Llyiahf/vczjk/e45;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ij8;I)V

    move-object/from16 v1, v20

    new-instance v2, Llyiahf/vczjk/zm;

    invoke-direct {v2, v13, v14, v1}, Llyiahf/vczjk/zm;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v9, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_13
    if-eq v11, v10, :cond_29

    const/16 v41, 0x1

    add-int/lit8 v11, v11, 0x1

    move/from16 v4, p1

    move-object/from16 v5, v40

    move/from16 v1, v42

    const/4 v2, 0x1

    goto/16 :goto_2

    :cond_28
    move-object/from16 v40, v5

    :cond_29
    new-instance v1, Llyiahf/vczjk/an;

    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/cn;->OooO00o:Llyiahf/vczjk/an;

    invoke-virtual {v9}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_2a

    const/4 v6, 0x0

    goto :goto_14

    :cond_2a
    move-object v6, v9

    :goto_14
    invoke-direct {v1, v6, v2}, Llyiahf/vczjk/an;-><init>(Ljava/util/List;Ljava/lang/String;)V

    move-object v6, v1

    goto :goto_15

    :cond_2b
    move-object/from16 v40, v5

    const/4 v6, 0x0

    :goto_15
    if-nez v6, :cond_2c

    goto/16 :goto_16

    :cond_2c
    iget-object v1, v0, Llyiahf/vczjk/ck9;->this$0:Llyiahf/vczjk/mk9;

    invoke-virtual {v1}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v1

    iget-object v2, v0, Llyiahf/vczjk/ck9;->this$0:Llyiahf/vczjk/mk9;

    invoke-virtual {v2}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v2

    iget-object v2, v2, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v2, v2, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v2

    invoke-static {v1, v2}, Llyiahf/vczjk/cl6;->OooOO0O(Llyiahf/vczjk/gl9;I)Llyiahf/vczjk/an;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/ym;

    invoke-direct {v2, v1}, Llyiahf/vczjk/ym;-><init>(Llyiahf/vczjk/an;)V

    invoke-virtual {v2, v6}, Llyiahf/vczjk/ym;->OooO0O0(Llyiahf/vczjk/an;)V

    invoke-virtual {v2}, Llyiahf/vczjk/ym;->OooO0OO()Llyiahf/vczjk/an;

    move-result-object v1

    iget-object v2, v0, Llyiahf/vczjk/ck9;->this$0:Llyiahf/vczjk/mk9;

    invoke-virtual {v2}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/ck9;->this$0:Llyiahf/vczjk/mk9;

    invoke-virtual {v3}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v3

    iget-object v3, v3, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v3, v3, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v3

    invoke-static {v2, v3}, Llyiahf/vczjk/cl6;->OooOO0(Llyiahf/vczjk/gl9;I)Llyiahf/vczjk/an;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/ym;

    invoke-direct {v3, v1}, Llyiahf/vczjk/ym;-><init>(Llyiahf/vczjk/an;)V

    invoke-virtual {v3, v2}, Llyiahf/vczjk/ym;->OooO0O0(Llyiahf/vczjk/an;)V

    invoke-virtual {v3}, Llyiahf/vczjk/ym;->OooO0OO()Llyiahf/vczjk/an;

    move-result-object v1

    iget-object v2, v0, Llyiahf/vczjk/ck9;->this$0:Llyiahf/vczjk/mk9;

    invoke-virtual {v2}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v2

    iget-wide v2, v2, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v2, v3}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result v2

    iget-object v3, v6, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v3

    add-int/2addr v3, v2

    iget-object v2, v0, Llyiahf/vczjk/ck9;->this$0:Llyiahf/vczjk/mk9;

    invoke-static {v3, v3}, Llyiahf/vczjk/rd3;->OooO0O0(II)J

    move-result-wide v3

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1, v3, v4}, Llyiahf/vczjk/mk9;->OooO0o0(Llyiahf/vczjk/an;J)Llyiahf/vczjk/gl9;

    move-result-object v1

    iget-object v2, v0, Llyiahf/vczjk/ck9;->this$0:Llyiahf/vczjk/mk9;

    iget-object v2, v2, Llyiahf/vczjk/mk9;->OooO0OO:Llyiahf/vczjk/rm4;

    invoke-interface {v2, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v1, v0, Llyiahf/vczjk/ck9;->this$0:Llyiahf/vczjk/mk9;

    sget-object v2, Llyiahf/vczjk/vl3;->OooOOO0:Llyiahf/vczjk/vl3;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/mk9;->OooOOo0(Llyiahf/vczjk/vl3;)V

    iget-object v1, v0, Llyiahf/vczjk/ck9;->this$0:Llyiahf/vczjk/mk9;

    iget-object v1, v1, Llyiahf/vczjk/mk9;->OooO00o:Llyiahf/vczjk/l8a;

    const/4 v2, 0x1

    iput-boolean v2, v1, Llyiahf/vczjk/l8a;->OooO0o0:Z

    return-object v40

    :cond_2d
    move-object/from16 v40, v5

    :goto_16
    return-object v40
.end method
