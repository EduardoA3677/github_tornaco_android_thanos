.class public final Llyiahf/vczjk/gc;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u22;
.implements Landroid/view/View$OnAttachStateChangeListener;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/da;

.field public final OooOOO0:Llyiahf/vczjk/xa;

.field public OooOOOO:Llyiahf/vczjk/jm1;

.field public final OooOOOo:Ljava/util/ArrayList;

.field public OooOOo:Llyiahf/vczjk/cc;

.field public final OooOOo0:J

.field public OooOOoo:Z

.field public final OooOo:Llyiahf/vczjk/or5;

.field public final OooOo0:Landroid/os/Handler;

.field public final OooOo00:Llyiahf/vczjk/jj0;

.field public OooOo0O:Llyiahf/vczjk/or5;

.field public OooOo0o:J

.field public OooOoO:Z

.field public OooOoO0:Llyiahf/vczjk/se8;

.field public final OooOoOO:Llyiahf/vczjk/oO0O00o0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xa;Llyiahf/vczjk/da;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gc;->OooOOO0:Llyiahf/vczjk/xa;

    iput-object p2, p0, Llyiahf/vczjk/gc;->OooOOO:Llyiahf/vczjk/da;

    new-instance p2, Ljava/util/ArrayList;

    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/gc;->OooOOOo:Ljava/util/ArrayList;

    const-wide/16 v0, 0x64

    iput-wide v0, p0, Llyiahf/vczjk/gc;->OooOOo0:J

    sget-object p2, Llyiahf/vczjk/cc;->OooOOO0:Llyiahf/vczjk/cc;

    iput-object p2, p0, Llyiahf/vczjk/gc;->OooOOo:Llyiahf/vczjk/cc;

    const/4 p2, 0x1

    iput-boolean p2, p0, Llyiahf/vczjk/gc;->OooOOoo:Z

    const/4 v0, 0x0

    const/4 v1, 0x6

    invoke-static {p2, v1, v0}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/gc;->OooOo00:Llyiahf/vczjk/jj0;

    new-instance p2, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v0

    invoke-direct {p2, v0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    iput-object p2, p0, Llyiahf/vczjk/gc;->OooOo0:Landroid/os/Handler;

    sget-object p2, Llyiahf/vczjk/t14;->OooO00o:Llyiahf/vczjk/or5;

    const-string v0, "null cannot be cast to non-null type androidx.collection.IntObjectMap<V of androidx.collection.IntObjectMapKt.intObjectMapOf>"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p2, p0, Llyiahf/vczjk/gc;->OooOo0O:Llyiahf/vczjk/or5;

    new-instance v1, Llyiahf/vczjk/or5;

    invoke-direct {v1}, Llyiahf/vczjk/or5;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/gc;->OooOo:Llyiahf/vczjk/or5;

    new-instance v1, Llyiahf/vczjk/se8;

    invoke-virtual {p1}, Llyiahf/vczjk/xa;->getSemanticsOwner()Llyiahf/vczjk/ue8;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/ue8;->OooO00o()Llyiahf/vczjk/re8;

    move-result-object p1

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/se8;-><init>(Llyiahf/vczjk/re8;Llyiahf/vczjk/s14;)V

    iput-object v1, p0, Llyiahf/vczjk/gc;->OooOoO0:Llyiahf/vczjk/se8;

    new-instance p1, Llyiahf/vczjk/oO0O00o0;

    const/4 p2, 0x7

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/oO0O00o0;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Llyiahf/vczjk/gc;->OooOoOO:Llyiahf/vczjk/oO0O00o0;

    return-void
.end method


# virtual methods
.method public final OooO(ILjava/lang/String;)V
    .locals 5

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1d

    if-ge v0, v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object v2, p0, Llyiahf/vczjk/gc;->OooOOOO:Llyiahf/vczjk/jm1;

    if-nez v2, :cond_1

    goto :goto_0

    :cond_1
    int-to-long v3, p1

    invoke-virtual {v2, v3, v4}, Llyiahf/vczjk/jm1;->OooO00o(J)Landroid/view/autofill/AutofillId;

    move-result-object p1

    if-eqz p1, :cond_3

    if-lt v0, v1, :cond_2

    iget-object v0, v2, Llyiahf/vczjk/jm1;->OooO00o:Ljava/lang/Object;

    invoke-static {v0}, Llyiahf/vczjk/r9;->OooO(Ljava/lang/Object;)Landroid/view/contentcapture/ContentCaptureSession;

    move-result-object v0

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/xo;->OooOO0O(Landroid/view/contentcapture/ContentCaptureSession;Landroid/view/autofill/AutofillId;Ljava/lang/String;)V

    :cond_2
    :goto_0
    return-void

    :cond_3
    const-string p1, "Invalid content capture ID"

    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooOOOo(Ljava/lang/String;)Llyiahf/vczjk/k61;

    move-result-object p1

    throw p1
.end method

.method public final OooO00o(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 9

    instance-of v0, p1, Llyiahf/vczjk/dc;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/dc;

    iget v1, v0, Llyiahf/vczjk/dc;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/dc;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/dc;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/dc;-><init>(Llyiahf/vczjk/gc;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/dc;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/dc;->label:I

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v2, :cond_4

    if-eq v2, v4, :cond_3

    if-ne v2, v3, :cond_2

    iget-object v2, v0, Llyiahf/vczjk/dc;->L$1:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ej0;

    iget-object v5, v0, Llyiahf/vczjk/dc;->L$0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/gc;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :cond_1
    move-object p1, v5

    goto :goto_1

    :cond_2
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    iget-object v2, v0, Llyiahf/vczjk/dc;->L$1:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ej0;

    iget-object v5, v0, Llyiahf/vczjk/dc;->L$0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/gc;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_4
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/gc;->OooOo00:Llyiahf/vczjk/jj0;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/ej0;

    invoke-direct {v2, p1}, Llyiahf/vczjk/ej0;-><init>(Llyiahf/vczjk/jj0;)V

    move-object p1, p0

    :goto_1
    iput-object p1, v0, Llyiahf/vczjk/dc;->L$0:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/dc;->L$1:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/dc;->label:I

    invoke-virtual {v2, v0}, Llyiahf/vczjk/ej0;->OooO0O0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v1, :cond_5

    goto :goto_3

    :cond_5
    move-object v8, v5

    move-object v5, p1

    move-object p1, v8

    :goto_2
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-eqz p1, :cond_8

    invoke-virtual {v2}, Llyiahf/vczjk/ej0;->OooO0OO()Ljava/lang/Object;

    invoke-virtual {v5}, Llyiahf/vczjk/gc;->OooO0o0()Z

    move-result p1

    if-eqz p1, :cond_6

    invoke-virtual {v5}, Llyiahf/vczjk/gc;->OooO0o()V

    :cond_6
    iget-boolean p1, v5, Llyiahf/vczjk/gc;->OooOoO:Z

    if-nez p1, :cond_7

    iput-boolean v4, v5, Llyiahf/vczjk/gc;->OooOoO:Z

    iget-object p1, v5, Llyiahf/vczjk/gc;->OooOo0:Landroid/os/Handler;

    iget-object v6, v5, Llyiahf/vczjk/gc;->OooOoOO:Llyiahf/vczjk/oO0O00o0;

    invoke-virtual {p1, v6}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    :cond_7
    iput-object v5, v0, Llyiahf/vczjk/dc;->L$0:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/dc;->L$1:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/dc;->label:I

    iget-wide v6, v5, Llyiahf/vczjk/gc;->OooOOo0:J

    invoke-static {v6, v7, v0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_1

    :goto_3
    return-object v1

    :cond_8
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/re8;Llyiahf/vczjk/ze3;)V
    .locals 6

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v0, 0x4

    invoke-static {v0, p1}, Llyiahf/vczjk/re8;->OooO0oo(ILlyiahf/vczjk/re8;)Ljava/util/List;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result v0

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    if-ge v1, v0, :cond_1

    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/re8;

    invoke-virtual {p0}, Llyiahf/vczjk/gc;->OooO0OO()Llyiahf/vczjk/s14;

    move-result-object v5

    iget v4, v4, Llyiahf/vczjk/re8;->OooO0oO:I

    invoke-virtual {v5, v4}, Llyiahf/vczjk/s14;->OooO00o(I)Z

    move-result v4

    if-eqz v4, :cond_0

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-interface {p2, v4, v3}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v2, v2, 0x1

    :cond_0
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public final OooO0OO()Llyiahf/vczjk/s14;
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/gc;->OooOOoo:Z

    if-eqz v0, :cond_0

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/gc;->OooOOoo:Z

    iget-object v0, p0, Llyiahf/vczjk/gc;->OooOOO0:Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getSemanticsOwner()Llyiahf/vczjk/ue8;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/nqa;->OooOoOO(Llyiahf/vczjk/ue8;)Llyiahf/vczjk/or5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/gc;->OooOo0O:Llyiahf/vczjk/or5;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    iput-wide v0, p0, Llyiahf/vczjk/gc;->OooOo0o:J

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/gc;->OooOo0O:Llyiahf/vczjk/or5;

    return-object v0
.end method

.method public final OooO0o()V
    .locals 10

    const/4 v0, 0x0

    const/4 v1, 0x1

    iget-object v2, p0, Llyiahf/vczjk/gc;->OooOOOO:Llyiahf/vczjk/jm1;

    if-nez v2, :cond_0

    goto/16 :goto_2

    :cond_0
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v4, 0x1d

    if-ge v3, v4, :cond_1

    goto/16 :goto_2

    :cond_1
    iget-object v3, p0, Llyiahf/vczjk/gc;->OooOOOo:Ljava/util/ArrayList;

    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v5

    if-nez v5, :cond_7

    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v5

    move v6, v0

    :goto_0
    iget-object v7, v2, Llyiahf/vczjk/jm1;->OooO00o:Ljava/lang/Object;

    if-ge v6, v5, :cond_5

    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/hm1;

    iget-object v9, v8, Llyiahf/vczjk/hm1;->OooO0OO:Llyiahf/vczjk/im1;

    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    move-result v9

    if-eqz v9, :cond_3

    if-eq v9, v1, :cond_2

    goto :goto_1

    :cond_2
    iget v8, v8, Llyiahf/vczjk/hm1;->OooO00o:I

    int-to-long v8, v8

    invoke-virtual {v2, v8, v9}, Llyiahf/vczjk/jm1;->OooO00o(J)Landroid/view/autofill/AutofillId;

    move-result-object v8

    if-eqz v8, :cond_4

    sget v9, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v9, v4, :cond_4

    invoke-static {v7}, Llyiahf/vczjk/r9;->OooO(Ljava/lang/Object;)Landroid/view/contentcapture/ContentCaptureSession;

    move-result-object v7

    invoke-static {v7, v8}, Llyiahf/vczjk/xo;->OooOO0(Landroid/view/contentcapture/ContentCaptureSession;Landroid/view/autofill/AutofillId;)V

    goto :goto_1

    :cond_3
    iget-object v8, v8, Llyiahf/vczjk/hm1;->OooO0Oo:Llyiahf/vczjk/gv7;

    if-eqz v8, :cond_4

    sget v9, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v9, v4, :cond_4

    invoke-static {v7}, Llyiahf/vczjk/r9;->OooO(Ljava/lang/Object;)Landroid/view/contentcapture/ContentCaptureSession;

    move-result-object v7

    iget-object v8, v8, Llyiahf/vczjk/gv7;->OooOOO0:Ljava/lang/Object;

    check-cast v8, Landroid/view/ViewStructure;

    invoke-static {v7, v8}, Llyiahf/vczjk/xo;->OooO(Landroid/view/contentcapture/ContentCaptureSession;Landroid/view/ViewStructure;)V

    :cond_4
    :goto_1
    add-int/2addr v6, v1

    goto :goto_0

    :cond_5
    sget v5, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v5, v4, :cond_6

    invoke-static {v7}, Llyiahf/vczjk/r9;->OooO(Ljava/lang/Object;)Landroid/view/contentcapture/ContentCaptureSession;

    move-result-object v4

    iget-object v2, v2, Llyiahf/vczjk/jm1;->OooO0O0:Landroid/view/View;

    invoke-static {v2}, Llyiahf/vczjk/ll6;->OooO0o(Landroid/view/View;)Llyiahf/vczjk/sw7;

    move-result-object v2

    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v2, v2, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    invoke-static {v2}, Llyiahf/vczjk/cr;->OooO0o(Ljava/lang/Object;)Landroid/view/autofill/AutofillId;

    move-result-object v2

    new-array v1, v1, [J

    const-wide/high16 v5, -0x8000000000000000L

    aput-wide v5, v1, v0

    invoke-static {v4, v2, v1}, Llyiahf/vczjk/xo;->OooOO0o(Landroid/view/contentcapture/ContentCaptureSession;Landroid/view/autofill/AutofillId;[J)V

    :cond_6
    invoke-virtual {v3}, Ljava/util/ArrayList;->clear()V

    :cond_7
    :goto_2
    return-void
.end method

.method public final OooO0o0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gc;->OooOOOO:Llyiahf/vczjk/jm1;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/re8;Llyiahf/vczjk/se8;)V
    .locals 5

    new-instance v0, Llyiahf/vczjk/ec;

    invoke-direct {v0, p2, p0}, Llyiahf/vczjk/ec;-><init>(Llyiahf/vczjk/se8;Llyiahf/vczjk/gc;)V

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/gc;->OooO0O0(Llyiahf/vczjk/re8;Llyiahf/vczjk/ze3;)V

    const/4 p2, 0x4

    invoke-static {p2, p1}, Llyiahf/vczjk/re8;->OooO0oo(ILlyiahf/vczjk/re8;)Ljava/util/List;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result p2

    const/4 v0, 0x0

    :goto_0
    if-ge v0, p2, :cond_2

    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/re8;

    invoke-virtual {p0}, Llyiahf/vczjk/gc;->OooO0OO()Llyiahf/vczjk/s14;

    move-result-object v2

    iget v3, v1, Llyiahf/vczjk/re8;->OooO0oO:I

    invoke-virtual {v2, v3}, Llyiahf/vczjk/s14;->OooO00o(I)Z

    move-result v2

    if-eqz v2, :cond_1

    iget-object v2, p0, Llyiahf/vczjk/gc;->OooOo:Llyiahf/vczjk/or5;

    iget v3, v1, Llyiahf/vczjk/re8;->OooO0oO:I

    invoke-virtual {v2, v3}, Llyiahf/vczjk/s14;->OooO00o(I)Z

    move-result v4

    if-eqz v4, :cond_1

    invoke-virtual {v2, v3}, Llyiahf/vczjk/s14;->OooO0O0(I)Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_0

    check-cast v2, Llyiahf/vczjk/se8;

    invoke-virtual {p0, v1, v2}, Llyiahf/vczjk/gc;->OooO0oo(Llyiahf/vczjk/re8;Llyiahf/vczjk/se8;)V

    goto :goto_1

    :cond_0
    const-string p1, "node not present in pruned tree before this change"

    invoke-static {p1}, Llyiahf/vczjk/ix8;->OooOOOo(Ljava/lang/String;)Llyiahf/vczjk/k61;

    move-result-object p1

    throw p1

    :cond_1
    :goto_1
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_2
    return-void
.end method

.method public final OooOO0(ILlyiahf/vczjk/re8;)V
    .locals 21

    move-object/from16 v0, p0

    move-object/from16 v1, p2

    invoke-virtual {v0}, Llyiahf/vczjk/gc;->OooO0o0()Z

    move-result v2

    if-nez v2, :cond_0

    return-void

    :cond_0
    iget-object v2, v1, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    sget-object v3, Llyiahf/vczjk/ve8;->OooOoo0:Llyiahf/vczjk/ze8;

    iget-object v2, v2, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    const/4 v4, 0x0

    if-nez v3, :cond_1

    move-object v3, v4

    :cond_1
    check-cast v3, Ljava/lang/Boolean;

    iget-object v5, v0, Llyiahf/vczjk/gc;->OooOOo:Llyiahf/vczjk/cc;

    sget-object v6, Llyiahf/vczjk/cc;->OooOOO0:Llyiahf/vczjk/cc;

    if-ne v5, v6, :cond_3

    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_3

    sget-object v3, Llyiahf/vczjk/ie8;->OooOO0o:Llyiahf/vczjk/ze8;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_2

    move-object v2, v4

    :cond_2
    check-cast v2, Llyiahf/vczjk/o0O00O;

    if-eqz v2, :cond_5

    iget-object v2, v2, Llyiahf/vczjk/o0O00O;->OooO0O0:Llyiahf/vczjk/cf3;

    check-cast v2, Llyiahf/vczjk/oe3;

    if-eqz v2, :cond_5

    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-interface {v2, v3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    goto :goto_0

    :cond_3
    iget-object v5, v0, Llyiahf/vczjk/gc;->OooOOo:Llyiahf/vczjk/cc;

    sget-object v6, Llyiahf/vczjk/cc;->OooOOO:Llyiahf/vczjk/cc;

    if-ne v5, v6, :cond_5

    sget-object v5, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_5

    sget-object v3, Llyiahf/vczjk/ie8;->OooOO0o:Llyiahf/vczjk/ze8;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_4

    move-object v2, v4

    :cond_4
    check-cast v2, Llyiahf/vczjk/o0O00O;

    if-eqz v2, :cond_5

    iget-object v2, v2, Llyiahf/vczjk/o0O00O;->OooO0O0:Llyiahf/vczjk/cf3;

    check-cast v2, Llyiahf/vczjk/oe3;

    if-eqz v2, :cond_5

    sget-object v3, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-interface {v2, v3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    :cond_5
    :goto_0
    iget-object v2, v0, Llyiahf/vczjk/gc;->OooOOOO:Llyiahf/vczjk/jm1;

    if-nez v2, :cond_6

    :goto_1
    move-object/from16 v20, v4

    goto/16 :goto_4

    :cond_6
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v5, 0x1d

    if-ge v3, v5, :cond_7

    goto :goto_1

    :cond_7
    iget-object v6, v0, Llyiahf/vczjk/gc;->OooOOO0:Llyiahf/vczjk/xa;

    invoke-static {v6}, Llyiahf/vczjk/ll6;->OooO0o(Landroid/view/View;)Llyiahf/vczjk/sw7;

    move-result-object v6

    if-nez v6, :cond_8

    goto :goto_1

    :cond_8
    invoke-virtual {v1}, Llyiahf/vczjk/re8;->OooOO0()Llyiahf/vczjk/re8;

    move-result-object v7

    if-eqz v7, :cond_9

    iget v6, v7, Llyiahf/vczjk/re8;->OooO0oO:I

    int-to-long v6, v6

    invoke-virtual {v2, v6, v7}, Llyiahf/vczjk/jm1;->OooO00o(J)Landroid/view/autofill/AutofillId;

    move-result-object v6

    if-nez v6, :cond_a

    goto :goto_1

    :cond_9
    iget-object v6, v6, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    invoke-static {v6}, Llyiahf/vczjk/cr;->OooO0o(Ljava/lang/Object;)Landroid/view/autofill/AutofillId;

    move-result-object v6

    :cond_a
    iget v7, v1, Llyiahf/vczjk/re8;->OooO0oO:I

    int-to-long v8, v7

    if-lt v3, v5, :cond_b

    iget-object v2, v2, Llyiahf/vczjk/jm1;->OooO00o:Ljava/lang/Object;

    invoke-static {v2}, Llyiahf/vczjk/r9;->OooO(Ljava/lang/Object;)Landroid/view/contentcapture/ContentCaptureSession;

    move-result-object v2

    invoke-static {v2, v6, v8, v9}, Llyiahf/vczjk/xo;->OooO0oo(Landroid/view/contentcapture/ContentCaptureSession;Landroid/view/autofill/AutofillId;J)Landroid/view/ViewStructure;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/gv7;

    invoke-direct {v3, v2}, Llyiahf/vczjk/gv7;-><init>(Ljava/lang/Object;)V

    goto :goto_2

    :cond_b
    move-object v3, v4

    :goto_2
    if-nez v3, :cond_c

    goto :goto_1

    :cond_c
    sget-object v2, Llyiahf/vczjk/ve8;->Oooo0:Llyiahf/vczjk/ze8;

    iget-object v5, v1, Llyiahf/vczjk/re8;->OooO0Oo:Llyiahf/vczjk/je8;

    iget-object v6, v5, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/js5;->OooO0OO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_d

    goto :goto_1

    :cond_d
    iget-object v2, v3, Llyiahf/vczjk/gv7;->OooOOO0:Ljava/lang/Object;

    move-object v8, v2

    check-cast v8, Landroid/view/ViewStructure;

    invoke-virtual {v8}, Landroid/view/ViewStructure;->getExtras()Landroid/os/Bundle;

    move-result-object v2

    if-eqz v2, :cond_e

    const-string v9, "android.view.contentcapture.EventTimestamp"

    iget-wide v10, v0, Llyiahf/vczjk/gc;->OooOo0o:J

    invoke-virtual {v2, v9, v10, v11}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    const-string v9, "android.view.ViewStructure.extra.EXTRA_VIEW_NODE_INDEX"

    move/from16 v10, p1

    invoke-virtual {v2, v9, v10}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    :cond_e
    sget-object v2, Llyiahf/vczjk/ve8;->OooOo:Llyiahf/vczjk/ze8;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_f

    move-object v2, v4

    :cond_f
    check-cast v2, Ljava/lang/String;

    if-eqz v2, :cond_10

    invoke-virtual {v8, v7, v4, v4, v2}, Landroid/view/ViewStructure;->setId(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    :cond_10
    sget-object v2, Llyiahf/vczjk/ve8;->OooOOO0:Llyiahf/vczjk/ze8;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_11

    move-object v2, v4

    :cond_11
    check-cast v2, Ljava/lang/Boolean;

    if-eqz v2, :cond_12

    const-string v2, "android.widget.ViewGroup"

    invoke-virtual {v8, v2}, Landroid/view/ViewStructure;->setClassName(Ljava/lang/String;)V

    :cond_12
    sget-object v2, Llyiahf/vczjk/ve8;->OooOoO:Llyiahf/vczjk/ze8;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_13

    move-object v2, v4

    :cond_13
    check-cast v2, Ljava/util/List;

    const/16 v7, 0x3e

    const-string v9, "\n"

    if-eqz v2, :cond_14

    const-string v10, "android.widget.TextView"

    invoke-virtual {v8, v10}, Landroid/view/ViewStructure;->setClassName(Ljava/lang/String;)V

    invoke-static {v2, v9, v4, v7}, Llyiahf/vczjk/r15;->OooO0O0(Ljava/util/List;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v8, v2}, Landroid/view/ViewStructure;->setText(Ljava/lang/CharSequence;)V

    :cond_14
    sget-object v2, Llyiahf/vczjk/ve8;->OooOooO:Llyiahf/vczjk/ze8;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_15

    move-object v2, v4

    :cond_15
    check-cast v2, Llyiahf/vczjk/an;

    if-eqz v2, :cond_16

    const-string v10, "android.widget.EditText"

    invoke-virtual {v8, v10}, Landroid/view/ViewStructure;->setClassName(Ljava/lang/String;)V

    invoke-virtual {v8, v2}, Landroid/view/ViewStructure;->setText(Ljava/lang/CharSequence;)V

    :cond_16
    sget-object v2, Llyiahf/vczjk/ve8;->OooO00o:Llyiahf/vczjk/ze8;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_17

    move-object v2, v4

    :cond_17
    check-cast v2, Ljava/util/List;

    if-eqz v2, :cond_18

    invoke-static {v2, v9, v4, v7}, Llyiahf/vczjk/r15;->OooO0O0(Ljava/util/List;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v8, v2}, Landroid/view/ViewStructure;->setContentDescription(Ljava/lang/CharSequence;)V

    :cond_18
    sget-object v2, Llyiahf/vczjk/ve8;->OooOo0o:Llyiahf/vczjk/ze8;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_19

    move-object v2, v4

    :cond_19
    check-cast v2, Llyiahf/vczjk/gu7;

    if-eqz v2, :cond_1a

    iget v2, v2, Llyiahf/vczjk/gu7;->OooO00o:I

    invoke-static {v2}, Llyiahf/vczjk/nqa;->o000oOoO(I)Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_1a

    invoke-virtual {v8, v2}, Landroid/view/ViewStructure;->setClassName(Ljava/lang/String;)V

    :cond_1a
    invoke-static {v5}, Llyiahf/vczjk/nqa;->Oooo000(Llyiahf/vczjk/je8;)Llyiahf/vczjk/mm9;

    move-result-object v2

    if-eqz v2, :cond_1b

    iget-object v2, v2, Llyiahf/vczjk/mm9;->OooO00o:Llyiahf/vczjk/lm9;

    iget-object v5, v2, Llyiahf/vczjk/lm9;->OooO0O0:Llyiahf/vczjk/rn9;

    iget-object v5, v5, Llyiahf/vczjk/rn9;->OooO00o:Llyiahf/vczjk/dy8;

    iget-wide v5, v5, Llyiahf/vczjk/dy8;->OooO0O0:J

    invoke-static {v5, v6}, Llyiahf/vczjk/un9;->OooO0OO(J)F

    move-result v5

    iget-object v2, v2, Llyiahf/vczjk/lm9;->OooO0oO:Llyiahf/vczjk/f62;

    invoke-interface {v2}, Llyiahf/vczjk/f62;->OooO0O0()F

    move-result v6

    mul-float/2addr v6, v5

    invoke-interface {v2}, Llyiahf/vczjk/f62;->o000oOoO()F

    move-result v2

    mul-float/2addr v2, v6

    const/4 v5, 0x0

    invoke-virtual {v8, v2, v5, v5, v5}, Landroid/view/ViewStructure;->setTextStyle(FIII)V

    :cond_1b
    invoke-virtual {v1}, Llyiahf/vczjk/re8;->OooOO0()Llyiahf/vczjk/re8;

    move-result-object v2

    sget-object v5, Llyiahf/vczjk/wj7;->OooO0o0:Llyiahf/vczjk/wj7;

    if-nez v2, :cond_1c

    goto :goto_3

    :cond_1c
    invoke-virtual {v1}, Llyiahf/vczjk/re8;->OooO0OO()Llyiahf/vczjk/v16;

    move-result-object v6

    if-eqz v6, :cond_1e

    invoke-virtual {v6}, Llyiahf/vczjk/v16;->o000OO()Llyiahf/vczjk/jl5;

    move-result-object v7

    iget-boolean v7, v7, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v7, :cond_1d

    move-object v4, v6

    :cond_1d
    if-eqz v4, :cond_1e

    iget-object v2, v2, Llyiahf/vczjk/re8;->OooO00o:Llyiahf/vczjk/jl5;

    const/16 v5, 0x8

    invoke-static {v2, v5}, Llyiahf/vczjk/yi4;->o00ooo(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/v16;

    move-result-object v2

    const/4 v5, 0x1

    invoke-virtual {v2, v4, v5}, Llyiahf/vczjk/v16;->OooOOO0(Llyiahf/vczjk/xn4;Z)Llyiahf/vczjk/wj7;

    move-result-object v5

    :cond_1e
    :goto_3
    iget v2, v5, Llyiahf/vczjk/wj7;->OooO00o:F

    float-to-int v9, v2

    iget v4, v5, Llyiahf/vczjk/wj7;->OooO0O0:F

    float-to-int v10, v4

    iget v6, v5, Llyiahf/vczjk/wj7;->OooO0OO:F

    sub-float/2addr v6, v2

    float-to-int v13, v6

    iget v2, v5, Llyiahf/vczjk/wj7;->OooO0Oo:F

    sub-float/2addr v2, v4

    float-to-int v14, v2

    const/4 v11, 0x0

    const/4 v12, 0x0

    invoke-virtual/range {v8 .. v14}, Landroid/view/ViewStructure;->setDimens(IIIIII)V

    move-object/from16 v20, v3

    :goto_4
    if-nez v20, :cond_1f

    goto :goto_5

    :cond_1f
    new-instance v15, Llyiahf/vczjk/hm1;

    iget-wide v2, v0, Llyiahf/vczjk/gc;->OooOo0o:J

    sget-object v19, Llyiahf/vczjk/im1;->OooOOO0:Llyiahf/vczjk/im1;

    iget v4, v1, Llyiahf/vczjk/re8;->OooO0oO:I

    move-wide/from16 v17, v2

    move/from16 v16, v4

    invoke-direct/range {v15 .. v20}, Llyiahf/vczjk/hm1;-><init>(IJLlyiahf/vczjk/im1;Llyiahf/vczjk/gv7;)V

    iget-object v2, v0, Llyiahf/vczjk/gc;->OooOOOo:Ljava/util/ArrayList;

    invoke-virtual {v2, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_5
    new-instance v2, Llyiahf/vczjk/fc;

    invoke-direct {v2, v0}, Llyiahf/vczjk/fc;-><init>(Llyiahf/vczjk/gc;)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/gc;->OooO0O0(Llyiahf/vczjk/re8;Llyiahf/vczjk/ze3;)V

    return-void
.end method

.method public final OooOO0O(Llyiahf/vczjk/re8;)V
    .locals 7

    invoke-virtual {p0}, Llyiahf/vczjk/gc;->OooO0o0()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_1

    :cond_0
    iget v2, p1, Llyiahf/vczjk/re8;->OooO0oO:I

    new-instance v1, Llyiahf/vczjk/hm1;

    iget-wide v3, p0, Llyiahf/vczjk/gc;->OooOo0o:J

    sget-object v5, Llyiahf/vczjk/im1;->OooOOO:Llyiahf/vczjk/im1;

    const/4 v6, 0x0

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/hm1;-><init>(IJLlyiahf/vczjk/im1;Llyiahf/vczjk/gv7;)V

    iget-object v0, p0, Llyiahf/vczjk/gc;->OooOOOo:Ljava/util/ArrayList;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    const/4 v0, 0x4

    invoke-static {v0, p1}, Llyiahf/vczjk/re8;->OooO0oo(ILlyiahf/vczjk/re8;)Ljava/util/List;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_1

    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/re8;

    invoke-virtual {p0, v2}, Llyiahf/vczjk/gc;->OooOO0O(Llyiahf/vczjk/re8;)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    :goto_1
    return-void
.end method

.method public final onStart(Llyiahf/vczjk/uy4;)V
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/gc;->OooOOO:Llyiahf/vczjk/da;

    invoke-virtual {p1}, Llyiahf/vczjk/da;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/jm1;

    iput-object p1, p0, Llyiahf/vczjk/gc;->OooOOOO:Llyiahf/vczjk/jm1;

    iget-object p1, p0, Llyiahf/vczjk/gc;->OooOOO0:Llyiahf/vczjk/xa;

    invoke-virtual {p1}, Llyiahf/vczjk/xa;->getSemanticsOwner()Llyiahf/vczjk/ue8;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/ue8;->OooO00o()Llyiahf/vczjk/re8;

    move-result-object p1

    const/4 v0, -0x1

    invoke-virtual {p0, v0, p1}, Llyiahf/vczjk/gc;->OooOO0(ILlyiahf/vczjk/re8;)V

    invoke-virtual {p0}, Llyiahf/vczjk/gc;->OooO0o()V

    return-void
.end method

.method public final onStop(Llyiahf/vczjk/uy4;)V
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/gc;->OooOOO0:Llyiahf/vczjk/xa;

    invoke-virtual {p1}, Llyiahf/vczjk/xa;->getSemanticsOwner()Llyiahf/vczjk/ue8;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/ue8;->OooO00o()Llyiahf/vczjk/re8;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/gc;->OooOO0O(Llyiahf/vczjk/re8;)V

    invoke-virtual {p0}, Llyiahf/vczjk/gc;->OooO0o()V

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/gc;->OooOOOO:Llyiahf/vczjk/jm1;

    return-void
.end method

.method public final onViewAttachedToWindow(Landroid/view/View;)V
    .locals 0

    return-void
.end method

.method public final onViewDetachedFromWindow(Landroid/view/View;)V
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/gc;->OooOo0:Landroid/os/Handler;

    iget-object v0, p0, Llyiahf/vczjk/gc;->OooOoOO:Llyiahf/vczjk/oO0O00o0;

    invoke-virtual {p1, v0}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/gc;->OooOOOO:Llyiahf/vczjk/jm1;

    return-void
.end method
