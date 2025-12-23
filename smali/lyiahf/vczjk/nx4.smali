.class public final Llyiahf/vczjk/nx4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/px6;


# instance fields
.field public OooO:Llyiahf/vczjk/wv3;

.field public final OooO00o:Landroid/view/View;

.field public final OooO0O0:Llyiahf/vczjk/p04;

.field public OooO0OO:Llyiahf/vczjk/oe3;

.field public OooO0Oo:Llyiahf/vczjk/oe3;

.field public OooO0o:Llyiahf/vczjk/mk9;

.field public OooO0o0:Llyiahf/vczjk/lx4;

.field public OooO0oO:Llyiahf/vczjk/gga;

.field public OooO0oo:Llyiahf/vczjk/gl9;

.field public final OooOO0:Ljava/util/ArrayList;

.field public final OooOO0O:Ljava/lang/Object;

.field public OooOO0o:Landroid/graphics/Rect;

.field public final OooOOO0:Llyiahf/vczjk/dx4;


# direct methods
.method public constructor <init>(Landroid/view/View;Llyiahf/vczjk/qd;Llyiahf/vczjk/p04;)V
    .locals 4

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/nx4;->OooO00o:Landroid/view/View;

    iput-object p3, p0, Llyiahf/vczjk/nx4;->OooO0O0:Llyiahf/vczjk/p04;

    sget-object p1, Llyiahf/vczjk/mo2;->Oooo0o:Llyiahf/vczjk/mo2;

    iput-object p1, p0, Llyiahf/vczjk/nx4;->OooO0OO:Llyiahf/vczjk/oe3;

    sget-object p1, Llyiahf/vczjk/mo2;->Oooo0oO:Llyiahf/vczjk/mo2;

    iput-object p1, p0, Llyiahf/vczjk/nx4;->OooO0Oo:Llyiahf/vczjk/oe3;

    new-instance p1, Llyiahf/vczjk/gl9;

    sget-wide v0, Llyiahf/vczjk/gn9;->OooO0O0:J

    const/4 v2, 0x4

    const-string v3, ""

    invoke-direct {p1, v3, v0, v1, v2}, Llyiahf/vczjk/gl9;-><init>(Ljava/lang/String;JI)V

    iput-object p1, p0, Llyiahf/vczjk/nx4;->OooO0oo:Llyiahf/vczjk/gl9;

    sget-object p1, Llyiahf/vczjk/wv3;->OooO0oO:Llyiahf/vczjk/wv3;

    iput-object p1, p0, Llyiahf/vczjk/nx4;->OooO:Llyiahf/vczjk/wv3;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/nx4;->OooOO0:Ljava/util/ArrayList;

    sget-object p1, Llyiahf/vczjk/ww4;->OooOOO:Llyiahf/vczjk/ww4;

    new-instance v0, Llyiahf/vczjk/mx4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/mx4;-><init>(Llyiahf/vczjk/nx4;)V

    invoke-static {p1, v0}, Llyiahf/vczjk/jp8;->Oooo00o(Llyiahf/vczjk/ww4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kp4;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/nx4;->OooOO0O:Ljava/lang/Object;

    new-instance p1, Llyiahf/vczjk/dx4;

    invoke-direct {p1, p2, p3}, Llyiahf/vczjk/dx4;-><init>(Llyiahf/vczjk/qd;Llyiahf/vczjk/p04;)V

    iput-object p1, p0, Llyiahf/vczjk/nx4;->OooOOO0:Llyiahf/vczjk/dx4;

    return-void
.end method


# virtual methods
.method public final OooO00o(Landroid/view/inputmethod/EditorInfo;)Llyiahf/vczjk/rj7;
    .locals 18

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    const/4 v2, 0x1

    iget-object v3, v0, Llyiahf/vczjk/nx4;->OooO0oo:Llyiahf/vczjk/gl9;

    iget-object v4, v3, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v4, v4, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    iget-object v5, v0, Llyiahf/vczjk/nx4;->OooO:Llyiahf/vczjk/wv3;

    iget v6, v5, Llyiahf/vczjk/wv3;->OooO0o0:I

    const/4 v7, 0x4

    const/4 v8, 0x5

    const/4 v9, 0x0

    const/4 v10, 0x7

    const/4 v11, 0x6

    const/4 v12, 0x3

    const/4 v13, 0x2

    iget-boolean v14, v5, Llyiahf/vczjk/wv3;->OooO00o:Z

    if-ne v6, v2, :cond_1

    if-eqz v14, :cond_0

    :goto_0
    move v6, v11

    goto :goto_1

    :cond_0
    move v6, v9

    goto :goto_1

    :cond_1
    if-nez v6, :cond_2

    move v6, v2

    goto :goto_1

    :cond_2
    if-ne v6, v13, :cond_3

    move v6, v13

    goto :goto_1

    :cond_3
    if-ne v6, v11, :cond_4

    move v6, v8

    goto :goto_1

    :cond_4
    if-ne v6, v8, :cond_5

    move v6, v10

    goto :goto_1

    :cond_5
    if-ne v6, v12, :cond_6

    move v6, v12

    goto :goto_1

    :cond_6
    if-ne v6, v7, :cond_7

    move v6, v7

    goto :goto_1

    :cond_7
    if-ne v6, v10, :cond_1c

    goto :goto_0

    :goto_1
    iput v6, v1, Landroid/view/inputmethod/EditorInfo;->imeOptions:I

    sget-object v6, Llyiahf/vczjk/e45;->OooOOOO:Llyiahf/vczjk/e45;

    iget-object v15, v5, Llyiahf/vczjk/wv3;->OooO0o:Llyiahf/vczjk/e45;

    invoke-static {v15, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_8

    const/4 v6, 0x0

    iput-object v6, v1, Landroid/view/inputmethod/EditorInfo;->hintLocales:Landroid/os/LocaleList;

    goto :goto_3

    :cond_8
    new-instance v6, Ljava/util/ArrayList;

    const/16 v10, 0xa

    invoke-static {v15, v10}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v10

    invoke-direct {v6, v10}, Ljava/util/ArrayList;-><init>(I)V

    iget-object v10, v15, Llyiahf/vczjk/e45;->OooOOO0:Ljava/util/List;

    invoke-interface {v10}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v10

    :goto_2
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    move-result v15

    if-eqz v15, :cond_9

    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Llyiahf/vczjk/d45;

    iget-object v15, v15, Llyiahf/vczjk/d45;->OooO00o:Ljava/util/Locale;

    invoke-virtual {v6, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_9
    new-array v10, v9, [Ljava/util/Locale;

    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v6

    check-cast v6, [Ljava/util/Locale;

    array-length v10, v6

    invoke-static {v6, v10}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v6

    check-cast v6, [Ljava/util/Locale;

    new-instance v10, Landroid/os/LocaleList;

    invoke-direct {v10, v6}, Landroid/os/LocaleList;-><init>([Ljava/util/Locale;)V

    iput-object v10, v1, Landroid/view/inputmethod/EditorInfo;->hintLocales:Landroid/os/LocaleList;

    :goto_3
    const/16 v6, 0x8

    iget v10, v5, Llyiahf/vczjk/wv3;->OooO0Oo:I

    if-ne v10, v2, :cond_a

    :goto_4
    move v7, v2

    goto :goto_5

    :cond_a
    if-ne v10, v13, :cond_b

    iget v7, v1, Landroid/view/inputmethod/EditorInfo;->imeOptions:I

    const/high16 v8, -0x80000000

    or-int/2addr v7, v8

    iput v7, v1, Landroid/view/inputmethod/EditorInfo;->imeOptions:I

    goto :goto_4

    :cond_b
    if-ne v10, v12, :cond_c

    move v7, v13

    goto :goto_5

    :cond_c
    if-ne v10, v7, :cond_d

    move v7, v12

    goto :goto_5

    :cond_d
    if-ne v10, v8, :cond_e

    const/16 v7, 0x11

    goto :goto_5

    :cond_e
    if-ne v10, v11, :cond_f

    const/16 v7, 0x21

    goto :goto_5

    :cond_f
    const/4 v7, 0x7

    if-ne v10, v7, :cond_10

    const/16 v7, 0x81

    goto :goto_5

    :cond_10
    if-ne v10, v6, :cond_11

    const/16 v7, 0x12

    goto :goto_5

    :cond_11
    const/16 v7, 0x9

    if-ne v10, v7, :cond_1b

    const/16 v7, 0x2002

    :goto_5
    iput v7, v1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    if-nez v14, :cond_12

    and-int/lit8 v8, v7, 0x1

    if-ne v8, v2, :cond_12

    const/high16 v8, 0x20000

    or-int/2addr v7, v8

    iput v7, v1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    iget v7, v5, Llyiahf/vczjk/wv3;->OooO0o0:I

    if-ne v7, v2, :cond_12

    iget v7, v1, Landroid/view/inputmethod/EditorInfo;->imeOptions:I

    const/high16 v8, 0x40000000    # 2.0f

    or-int/2addr v7, v8

    iput v7, v1, Landroid/view/inputmethod/EditorInfo;->imeOptions:I

    :cond_12
    iget v7, v1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    and-int/lit8 v8, v7, 0x1

    if-ne v8, v2, :cond_16

    iget v8, v5, Llyiahf/vczjk/wv3;->OooO0O0:I

    if-ne v8, v2, :cond_13

    or-int/lit16 v7, v7, 0x1000

    iput v7, v1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    goto :goto_6

    :cond_13
    if-ne v8, v13, :cond_14

    or-int/lit16 v7, v7, 0x2000

    iput v7, v1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    goto :goto_6

    :cond_14
    if-ne v8, v12, :cond_15

    or-int/lit16 v7, v7, 0x4000

    iput v7, v1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    :cond_15
    :goto_6
    iget-boolean v5, v5, Llyiahf/vczjk/wv3;->OooO0OO:Z

    if-eqz v5, :cond_16

    iget v5, v1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    const v7, 0x8000

    or-int/2addr v5, v7

    iput v5, v1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    :cond_16
    sget v5, Llyiahf/vczjk/gn9;->OooO0OO:I

    iget-wide v7, v3, Llyiahf/vczjk/gl9;->OooO0O0:J

    const/16 v3, 0x20

    shr-long v11, v7, v3

    long-to-int v3, v11

    iput v3, v1, Landroid/view/inputmethod/EditorInfo;->initialSelStart:I

    const-wide v11, 0xffffffffL

    and-long/2addr v7, v11

    long-to-int v3, v7

    iput v3, v1, Landroid/view/inputmethod/EditorInfo;->initialSelEnd:I

    invoke-static {v1, v4}, Llyiahf/vczjk/l4a;->Oooo0(Landroid/view/inputmethod/EditorInfo;Ljava/lang/CharSequence;)V

    iget v3, v1, Landroid/view/inputmethod/EditorInfo;->imeOptions:I

    const/high16 v4, 0x2000000

    or-int/2addr v3, v4

    iput v3, v1, Landroid/view/inputmethod/EditorInfo;->imeOptions:I

    sget-boolean v3, Llyiahf/vczjk/o79;->OooO00o:Z

    if-eqz v3, :cond_19

    const/4 v7, 0x7

    if-ne v10, v7, :cond_17

    goto :goto_7

    :cond_17
    if-ne v10, v6, :cond_18

    goto :goto_7

    :cond_18
    invoke-static {v1, v2}, Llyiahf/vczjk/l4a;->Oooo0O0(Landroid/view/inputmethod/EditorInfo;Z)V

    invoke-static {}, Llyiahf/vczjk/ld;->OooOOO0()Ljava/lang/Class;

    move-result-object v11

    invoke-static {}, Llyiahf/vczjk/ld;->OooOoO()Ljava/lang/Class;

    move-result-object v12

    invoke-static {}, Llyiahf/vczjk/ld;->OooOo0O()Ljava/lang/Class;

    move-result-object v13

    invoke-static {}, Llyiahf/vczjk/ld;->OooOo()Ljava/lang/Class;

    move-result-object v14

    invoke-static {}, Llyiahf/vczjk/ld;->OooOoo0()Ljava/lang/Class;

    move-result-object v15

    invoke-static {}, Llyiahf/vczjk/ld;->OooOoo()Ljava/lang/Class;

    move-result-object v16

    invoke-static {}, Llyiahf/vczjk/ld;->OooOooO()Ljava/lang/Class;

    move-result-object v17

    filled-new-array/range {v11 .. v17}, [Ljava/lang/Class;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    invoke-static {v1, v2}, Llyiahf/vczjk/ld;->OooOOOo(Landroid/view/inputmethod/EditorInfo;Ljava/util/List;)V

    invoke-static {}, Llyiahf/vczjk/ld;->OooOOO0()Ljava/lang/Class;

    move-result-object v2

    invoke-static {}, Llyiahf/vczjk/ld;->OooOoO()Ljava/lang/Class;

    move-result-object v3

    invoke-static {}, Llyiahf/vczjk/ld;->OooOo0O()Ljava/lang/Class;

    move-result-object v4

    invoke-static {}, Llyiahf/vczjk/ld;->OooOo()Ljava/lang/Class;

    move-result-object v5

    filled-new-array {v2, v3, v4, v5}, [Ljava/lang/Class;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/sy;->o0000O0O([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v2

    invoke-static {v1, v2}, Llyiahf/vczjk/ld;->OooOOo0(Landroid/view/inputmethod/EditorInfo;Ljava/util/Set;)V

    goto :goto_8

    :cond_19
    :goto_7
    invoke-static {v1, v9}, Llyiahf/vczjk/l4a;->Oooo0O0(Landroid/view/inputmethod/EditorInfo;Z)V

    :goto_8
    sget-object v2, Llyiahf/vczjk/hx4;->OooO00o:Llyiahf/vczjk/gx4;

    invoke-static {}, Llyiahf/vczjk/rl2;->OooO0Oo()Z

    move-result v2

    if-nez v2, :cond_1a

    goto :goto_9

    :cond_1a
    invoke-static {}, Llyiahf/vczjk/rl2;->OooO00o()Llyiahf/vczjk/rl2;

    move-result-object v2

    invoke-virtual {v2, v1}, Llyiahf/vczjk/rl2;->OooO(Landroid/view/inputmethod/EditorInfo;)V

    :goto_9
    iget-object v4, v0, Llyiahf/vczjk/nx4;->OooO0oo:Llyiahf/vczjk/gl9;

    iget-object v1, v0, Llyiahf/vczjk/nx4;->OooO:Llyiahf/vczjk/wv3;

    iget-boolean v6, v1, Llyiahf/vczjk/wv3;->OooO0OO:Z

    new-instance v5, Llyiahf/vczjk/sw7;

    const/16 v1, 0x15

    invoke-direct {v5, v0, v1}, Llyiahf/vczjk/sw7;-><init>(Ljava/lang/Object;I)V

    iget-object v7, v0, Llyiahf/vczjk/nx4;->OooO0o0:Llyiahf/vczjk/lx4;

    iget-object v8, v0, Llyiahf/vczjk/nx4;->OooO0o:Llyiahf/vczjk/mk9;

    iget-object v9, v0, Llyiahf/vczjk/nx4;->OooO0oO:Llyiahf/vczjk/gga;

    new-instance v3, Llyiahf/vczjk/rj7;

    invoke-direct/range {v3 .. v9}, Llyiahf/vczjk/rj7;-><init>(Llyiahf/vczjk/gl9;Llyiahf/vczjk/sw7;ZLlyiahf/vczjk/lx4;Llyiahf/vczjk/mk9;Llyiahf/vczjk/gga;)V

    iget-object v1, v0, Llyiahf/vczjk/nx4;->OooOO0:Ljava/util/ArrayList;

    new-instance v2, Ljava/lang/ref/WeakReference;

    invoke-direct {v2, v3}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-object v3

    :cond_1b
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "Invalid Keyboard Type"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1c
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "invalid ImeAction"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1
.end method
