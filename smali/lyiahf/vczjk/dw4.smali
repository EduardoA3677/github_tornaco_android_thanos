.class public final Llyiahf/vczjk/dw4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sa8;


# static fields
.field public static final OooOo0o:Llyiahf/vczjk/era;


# instance fields
.field public final OooO:Z

.field public final OooO00o:Llyiahf/vczjk/o0OoOo0;

.field public OooO0O0:Z

.field public OooO0OO:Llyiahf/vczjk/sv4;

.field public final OooO0Oo:Llyiahf/vczjk/tq4;

.field public final OooO0o:Llyiahf/vczjk/sr5;

.field public final OooO0o0:Llyiahf/vczjk/qs5;

.field public OooO0oO:F

.field public final OooO0oo:Llyiahf/vczjk/u32;

.field public OooOO0:Llyiahf/vczjk/ro4;

.field public final OooOO0O:Llyiahf/vczjk/ar4;

.field public final OooOO0o:Llyiahf/vczjk/g20;

.field public final OooOOO:Llyiahf/vczjk/vz5;

.field public final OooOOO0:Landroidx/compose/foundation/lazy/layout/OooO0OO;

.field public final OooOOOO:Llyiahf/vczjk/ku4;

.field public final OooOOOo:Llyiahf/vczjk/tg7;

.field public final OooOOo:Llyiahf/vczjk/qs5;

.field public final OooOOo0:Llyiahf/vczjk/hu4;

.field public final OooOOoo:Llyiahf/vczjk/qs5;

.field public final OooOo0:Llyiahf/vczjk/qs5;

.field public final OooOo00:Llyiahf/vczjk/qs5;

.field public final OooOo0O:Llyiahf/vczjk/ou4;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/ye1;->OooOo0o:Llyiahf/vczjk/ye1;

    sget-object v1, Llyiahf/vczjk/mo2;->Oooo0OO:Llyiahf/vczjk/mo2;

    invoke-static {v1, v0}, Llyiahf/vczjk/vc6;->Oooo0(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/era;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/dw4;->OooOo0o:Llyiahf/vczjk/era;

    return-void
.end method

.method public constructor <init>(II)V
    .locals 2

    new-instance v0, Llyiahf/vczjk/o0OoOo0;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    const/4 v1, -0x1

    iput v1, v0, Llyiahf/vczjk/o0OoOo0;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/dw4;->OooO00o:Llyiahf/vczjk/o0OoOo0;

    new-instance v0, Llyiahf/vczjk/tq4;

    const/4 v1, 0x1

    invoke-direct {v0, p1, p2, v1}, Llyiahf/vczjk/tq4;-><init>(III)V

    iput-object v0, p0, Llyiahf/vczjk/dw4;->OooO0Oo:Llyiahf/vczjk/tq4;

    sget-object p2, Llyiahf/vczjk/fw4;->OooO00o:Llyiahf/vczjk/sv4;

    sget-object v0, Llyiahf/vczjk/e86;->OooOOo0:Llyiahf/vczjk/e86;

    invoke-static {p2, v0}, Landroidx/compose/runtime/OooO0o;->OooO(Ljava/lang/Object;Llyiahf/vczjk/gw8;)Llyiahf/vczjk/qs5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/dw4;->OooO0o0:Llyiahf/vczjk/qs5;

    new-instance p2, Llyiahf/vczjk/sr5;

    invoke-direct {p2}, Llyiahf/vczjk/sr5;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/dw4;->OooO0o:Llyiahf/vczjk/sr5;

    new-instance p2, Llyiahf/vczjk/cw4;

    invoke-direct {p2, p0}, Llyiahf/vczjk/cw4;-><init>(Llyiahf/vczjk/dw4;)V

    new-instance v0, Llyiahf/vczjk/u32;

    invoke-direct {v0, p2}, Llyiahf/vczjk/u32;-><init>(Llyiahf/vczjk/oe3;)V

    iput-object v0, p0, Llyiahf/vczjk/dw4;->OooO0oo:Llyiahf/vczjk/u32;

    const/4 p2, 0x1

    iput-boolean p2, p0, Llyiahf/vczjk/dw4;->OooO:Z

    new-instance p2, Llyiahf/vczjk/ar4;

    const/4 v0, 0x1

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/ar4;-><init>(Llyiahf/vczjk/sa8;I)V

    iput-object p2, p0, Llyiahf/vczjk/dw4;->OooOO0O:Llyiahf/vczjk/ar4;

    new-instance p2, Llyiahf/vczjk/g20;

    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/dw4;->OooOO0o:Llyiahf/vczjk/g20;

    new-instance p2, Landroidx/compose/foundation/lazy/layout/OooO0OO;

    invoke-direct {p2}, Landroidx/compose/foundation/lazy/layout/OooO0OO;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/dw4;->OooOOO0:Landroidx/compose/foundation/lazy/layout/OooO0OO;

    new-instance p2, Llyiahf/vczjk/vz5;

    const/16 v0, 0x18

    invoke-direct {p2, v0}, Llyiahf/vczjk/vz5;-><init>(I)V

    iput-object p2, p0, Llyiahf/vczjk/dw4;->OooOOO:Llyiahf/vczjk/vz5;

    new-instance p2, Llyiahf/vczjk/ku4;

    new-instance v0, Llyiahf/vczjk/zv4;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/zv4;-><init>(Llyiahf/vczjk/dw4;I)V

    invoke-direct {p2, v0}, Llyiahf/vczjk/ku4;-><init>(Llyiahf/vczjk/oe3;)V

    iput-object p2, p0, Llyiahf/vczjk/dw4;->OooOOOO:Llyiahf/vczjk/ku4;

    new-instance p1, Llyiahf/vczjk/tg7;

    const/16 p2, 0x13

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/tg7;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Llyiahf/vczjk/dw4;->OooOOOo:Llyiahf/vczjk/tg7;

    new-instance p1, Llyiahf/vczjk/hu4;

    invoke-direct {p1}, Llyiahf/vczjk/hu4;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/dw4;->OooOOo0:Llyiahf/vczjk/hu4;

    invoke-static {}, Llyiahf/vczjk/zsa;->Oooo00o()Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/dw4;->OooOOo:Llyiahf/vczjk/qs5;

    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/dw4;->OooOOoo:Llyiahf/vczjk/qs5;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/dw4;->OooOo00:Llyiahf/vczjk/qs5;

    invoke-static {}, Llyiahf/vczjk/zsa;->Oooo00o()Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/dw4;->OooOo0:Llyiahf/vczjk/qs5;

    new-instance p1, Llyiahf/vczjk/ou4;

    invoke-direct {p1}, Llyiahf/vczjk/ou4;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/dw4;->OooOo0O:Llyiahf/vczjk/ou4;

    return-void
.end method

.method public synthetic constructor <init>(III)V
    .locals 0

    and-int/lit8 p2, p2, 0x1

    const/4 p3, 0x0

    if-eqz p2, :cond_0

    move p1, p3

    :cond_0
    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/dw4;-><init>(II)V

    return-void
.end method

.method public static OooO(Llyiahf/vczjk/dw4;ILlyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 3

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/bw4;

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-direct {v0, p0, p1, v2, v1}, Llyiahf/vczjk/bw4;-><init>(Llyiahf/vczjk/dw4;IILlyiahf/vczjk/yo1;)V

    sget-object p1, Llyiahf/vczjk/at5;->OooOOO0:Llyiahf/vczjk/at5;

    invoke-virtual {p0, p1, v0, p2}, Llyiahf/vczjk/dw4;->OooO0OO(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p0, p1, :cond_0

    return-object p0

    :cond_0
    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method


# virtual methods
.method public final OooO00o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/dw4;->OooO0oo:Llyiahf/vczjk/u32;

    invoke-virtual {v0}, Llyiahf/vczjk/u32;->OooO00o()Z

    move-result v0

    return v0
.end method

.method public final OooO0O0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/dw4;->OooOo00:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 5

    instance-of v0, p3, Llyiahf/vczjk/aw4;

    if-eqz v0, :cond_0

    move-object v0, p3

    check-cast v0, Llyiahf/vczjk/aw4;

    iget v1, v0, Llyiahf/vczjk/aw4;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/aw4;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/aw4;

    invoke-direct {v0, p0, p3}, Llyiahf/vczjk/aw4;-><init>(Llyiahf/vczjk/dw4;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p3, v0, Llyiahf/vczjk/aw4;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/aw4;->label:I

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v4, :cond_2

    if-ne v2, v3, :cond_1

    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object p1, v0, Llyiahf/vczjk/aw4;->L$2:Ljava/lang/Object;

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/ze3;

    iget-object p1, v0, Llyiahf/vczjk/aw4;->L$1:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/at5;

    iget-object v2, v0, Llyiahf/vczjk/aw4;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/dw4;

    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_3
    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iput-object p0, v0, Llyiahf/vczjk/aw4;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/aw4;->L$1:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/aw4;->L$2:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/aw4;->label:I

    iget-object p3, p0, Llyiahf/vczjk/dw4;->OooOO0o:Llyiahf/vczjk/g20;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/g20;->OooOO0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p3

    if-ne p3, v1, :cond_4

    goto :goto_2

    :cond_4
    move-object v2, p0

    :goto_1
    iget-object p3, v2, Llyiahf/vczjk/dw4;->OooO0oo:Llyiahf/vczjk/u32;

    const/4 v2, 0x0

    iput-object v2, v0, Llyiahf/vczjk/aw4;->L$0:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/aw4;->L$1:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/aw4;->L$2:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/aw4;->label:I

    invoke-virtual {p3, p1, p2, v0}, Llyiahf/vczjk/u32;->OooO0OO(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_5

    :goto_2
    return-object v1

    :cond_5
    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0Oo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/dw4;->OooOOoo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    return v0
.end method

.method public final OooO0o(Llyiahf/vczjk/sv4;ZZ)V
    .locals 8

    if-nez p2, :cond_0

    iget-boolean v0, p0, Llyiahf/vczjk/dw4;->OooO0O0:Z

    if-eqz v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/dw4;->OooO0OO:Llyiahf/vczjk/sv4;

    return-void

    :cond_0
    const/4 v0, 0x1

    if-eqz p2, :cond_1

    iput-boolean v0, p0, Llyiahf/vczjk/dw4;->OooO0O0:Z

    :cond_1
    iget-object v1, p1, Llyiahf/vczjk/sv4;->OooO00o:Llyiahf/vczjk/tv4;

    const/4 v2, 0x0

    if-eqz v1, :cond_2

    iget v3, v1, Llyiahf/vczjk/tv4;->OooO00o:I

    goto :goto_0

    :cond_2
    move v3, v2

    :goto_0
    iget v4, p1, Llyiahf/vczjk/sv4;->OooO0O0:I

    if-nez v3, :cond_4

    if-eqz v4, :cond_3

    goto :goto_1

    :cond_3
    move v3, v2

    goto :goto_2

    :cond_4
    :goto_1
    move v3, v0

    :goto_2
    iget-object v5, p0, Llyiahf/vczjk/dw4;->OooOo00:Llyiahf/vczjk/qs5;

    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v3

    check-cast v5, Llyiahf/vczjk/fw8;

    invoke-virtual {v5, v3}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v3, p0, Llyiahf/vczjk/dw4;->OooOOoo:Llyiahf/vczjk/qs5;

    iget-boolean v5, p1, Llyiahf/vczjk/sv4;->OooO0OO:Z

    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v5

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3, v5}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget v3, p0, Llyiahf/vczjk/dw4;->OooO0oO:F

    iget v5, p1, Llyiahf/vczjk/sv4;->OooO0Oo:F

    sub-float/2addr v3, v5

    iput v3, p0, Llyiahf/vczjk/dw4;->OooO0oO:F

    iget-object v3, p0, Llyiahf/vczjk/dw4;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    const-string v3, "scrollOffset should be non-negative"

    const/4 v5, 0x0

    iget-object v6, p0, Llyiahf/vczjk/dw4;->OooO0Oo:Llyiahf/vczjk/tq4;

    if-eqz p3, :cond_6

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    int-to-float p3, v4

    cmpl-float p3, p3, v5

    if-ltz p3, :cond_5

    goto :goto_3

    :cond_5
    invoke-static {v3}, Llyiahf/vczjk/sz3;->OooO0OO(Ljava/lang/String;)V

    :goto_3
    iget-object p3, v6, Llyiahf/vczjk/tq4;->OooO0OO:Llyiahf/vczjk/qr5;

    check-cast p3, Llyiahf/vczjk/bw8;

    invoke-virtual {p3, v4}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    goto :goto_7

    :cond_6
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p3, 0x0

    if-eqz v1, :cond_7

    iget-object v7, v1, Llyiahf/vczjk/tv4;->OooOO0o:Ljava/lang/Object;

    goto :goto_4

    :cond_7
    move-object v7, p3

    :goto_4
    iput-object v7, v6, Llyiahf/vczjk/tq4;->OooO0o0:Ljava/lang/Object;

    iget-boolean v7, v6, Llyiahf/vczjk/tq4;->OooO0Oo:Z

    if-nez v7, :cond_8

    iget v7, p1, Llyiahf/vczjk/sv4;->OooOOO:I

    if-lez v7, :cond_b

    :cond_8
    iput-boolean v0, v6, Llyiahf/vczjk/tq4;->OooO0Oo:Z

    int-to-float v7, v4

    cmpl-float v5, v7, v5

    if-ltz v5, :cond_9

    goto :goto_5

    :cond_9
    invoke-static {v3}, Llyiahf/vczjk/sz3;->OooO0OO(Ljava/lang/String;)V

    :goto_5
    if-eqz v1, :cond_a

    iget v2, v1, Llyiahf/vczjk/tv4;->OooO00o:I

    :cond_a
    invoke-virtual {v6, v2, v4}, Llyiahf/vczjk/tq4;->OooO0OO(II)V

    :cond_b
    iget-boolean v1, p0, Llyiahf/vczjk/dw4;->OooO:Z

    if-eqz v1, :cond_e

    iget-object v1, p0, Llyiahf/vczjk/dw4;->OooO00o:Llyiahf/vczjk/o0OoOo0;

    iget v2, v1, Llyiahf/vczjk/o0OoOo0;->OooO00o:I

    const/4 v3, -0x1

    if-eq v2, v3, :cond_e

    iget-object v2, p1, Llyiahf/vczjk/sv4;->OooOO0O:Ljava/lang/Object;

    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result v4

    if-nez v4, :cond_e

    iget-boolean v4, v1, Llyiahf/vczjk/o0OoOo0;->OooO0O0:Z

    if-eqz v4, :cond_c

    invoke-static {v2}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/gv4;

    check-cast v2, Llyiahf/vczjk/tv4;

    iget v2, v2, Llyiahf/vczjk/tv4;->OooO00o:I

    add-int/2addr v2, v0

    goto :goto_6

    :cond_c
    invoke-static {v2}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/gv4;

    check-cast v2, Llyiahf/vczjk/tv4;

    iget v2, v2, Llyiahf/vczjk/tv4;->OooO00o:I

    sub-int/2addr v2, v0

    :goto_6
    iget v0, v1, Llyiahf/vczjk/o0OoOo0;->OooO00o:I

    if-eq v0, v2, :cond_e

    iput v3, v1, Llyiahf/vczjk/o0OoOo0;->OooO00o:I

    iget-object v0, v1, Llyiahf/vczjk/o0OoOo0;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ju4;

    if-eqz v0, :cond_d

    invoke-interface {v0}, Llyiahf/vczjk/ju4;->cancel()V

    :cond_d
    iput-object p3, v1, Llyiahf/vczjk/o0OoOo0;->OooO0OO:Ljava/lang/Object;

    :cond_e
    :goto_7
    if-eqz p2, :cond_f

    iget-object p2, p1, Llyiahf/vczjk/sv4;->OooO:Llyiahf/vczjk/f62;

    iget-object p3, p1, Llyiahf/vczjk/sv4;->OooO0oo:Llyiahf/vczjk/xr1;

    iget-object v0, p0, Llyiahf/vczjk/dw4;->OooOo0O:Llyiahf/vczjk/ou4;

    iget p1, p1, Llyiahf/vczjk/sv4;->OooO0o:F

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/ou4;->OooO00o(FLlyiahf/vczjk/f62;Llyiahf/vczjk/xr1;)V

    :cond_f
    return-void
.end method

.method public final OooO0o0(F)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/dw4;->OooO0oo:Llyiahf/vczjk/u32;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/u32;->OooO0o0(F)F

    move-result p1

    return p1
.end method

.method public final OooO0oO()Llyiahf/vczjk/sv4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/dw4;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/sv4;

    return-object v0
.end method

.method public final OooO0oo(FLlyiahf/vczjk/sv4;)V
    .locals 10

    iget-boolean v0, p0, Llyiahf/vczjk/dw4;->OooO:Z

    if-eqz v0, :cond_6

    iget-object v0, p0, Llyiahf/vczjk/dw4;->OooO00o:Llyiahf/vczjk/o0OoOo0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, p2, Llyiahf/vczjk/sv4;->OooOO0O:Ljava/lang/Object;

    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_6

    const/4 v1, 0x0

    cmpg-float v1, p1, v1

    const/4 v2, 0x1

    if-gez v1, :cond_0

    move v1, v2

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    iget-object v3, p2, Llyiahf/vczjk/sv4;->OooOO0O:Ljava/lang/Object;

    if-eqz v1, :cond_1

    invoke-static {v3}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/gv4;

    check-cast v4, Llyiahf/vczjk/tv4;

    iget v4, v4, Llyiahf/vczjk/tv4;->OooO00o:I

    add-int/2addr v4, v2

    goto :goto_1

    :cond_1
    invoke-static {v3}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/gv4;

    check-cast v4, Llyiahf/vczjk/tv4;

    iget v4, v4, Llyiahf/vczjk/tv4;->OooO00o:I

    sub-int/2addr v4, v2

    :goto_1
    if-ltz v4, :cond_6

    iget v2, p2, Llyiahf/vczjk/sv4;->OooOOO:I

    if-ge v4, v2, :cond_6

    iget v2, v0, Llyiahf/vczjk/o0OoOo0;->OooO00o:I

    if-eq v4, v2, :cond_4

    iget-boolean v2, v0, Llyiahf/vczjk/o0OoOo0;->OooO0O0:Z

    if-eq v2, v1, :cond_2

    iget-object v2, v0, Llyiahf/vczjk/o0OoOo0;->OooO0OO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ju4;

    if-eqz v2, :cond_2

    invoke-interface {v2}, Llyiahf/vczjk/ju4;->cancel()V

    :cond_2
    iput-boolean v1, v0, Llyiahf/vczjk/o0OoOo0;->OooO0O0:Z

    iput v4, v0, Llyiahf/vczjk/o0OoOo0;->OooO00o:I

    iget-object v2, p0, Llyiahf/vczjk/dw4;->OooOOOo:Llyiahf/vczjk/tg7;

    iget-object v2, v2, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/dw4;

    invoke-static {}, Llyiahf/vczjk/wr6;->OooOOO0()Llyiahf/vczjk/nv8;

    move-result-object v5

    if-eqz v5, :cond_3

    invoke-virtual {v5}, Llyiahf/vczjk/nv8;->OooO0o0()Llyiahf/vczjk/oe3;

    move-result-object v6

    goto :goto_2

    :cond_3
    const/4 v6, 0x0

    :goto_2
    invoke-static {v5}, Llyiahf/vczjk/wr6;->OooOOOo(Llyiahf/vczjk/nv8;)Llyiahf/vczjk/nv8;

    move-result-object v7

    :try_start_0
    iget-object v8, v2, Llyiahf/vczjk/dw4;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v8, Llyiahf/vczjk/fw8;

    invoke-virtual {v8}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/sv4;

    iget-wide v8, v8, Llyiahf/vczjk/sv4;->OooOO0:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {v5, v7, v6}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    iget-object v2, v2, Llyiahf/vczjk/dw4;->OooOOOO:Llyiahf/vczjk/ku4;

    invoke-virtual {v2, v4, v8, v9}, Llyiahf/vczjk/ku4;->OooO00o(IJ)Llyiahf/vczjk/ju4;

    move-result-object v2

    iput-object v2, v0, Llyiahf/vczjk/o0OoOo0;->OooO0OO:Ljava/lang/Object;

    goto :goto_3

    :catchall_0
    move-exception p1

    invoke-static {v5, v7, v6}, Llyiahf/vczjk/wr6;->OooOo0O(Llyiahf/vczjk/nv8;Llyiahf/vczjk/nv8;Llyiahf/vczjk/oe3;)V

    throw p1

    :cond_4
    :goto_3
    if-eqz v1, :cond_5

    invoke-static {v3}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/gv4;

    check-cast v1, Llyiahf/vczjk/tv4;

    iget v2, v1, Llyiahf/vczjk/tv4;->OooOOOo:I

    iget v1, v1, Llyiahf/vczjk/tv4;->OooOOo0:I

    add-int/2addr v2, v1

    iget v1, p2, Llyiahf/vczjk/sv4;->OooOOo:I

    add-int/2addr v2, v1

    iget p2, p2, Llyiahf/vczjk/sv4;->OooOOO0:I

    sub-int/2addr v2, p2

    int-to-float p2, v2

    neg-float p1, p1

    cmpg-float p1, p2, p1

    if-gez p1, :cond_6

    iget-object p1, v0, Llyiahf/vczjk/o0OoOo0;->OooO0OO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/ju4;

    if-eqz p1, :cond_6

    invoke-interface {p1}, Llyiahf/vczjk/ju4;->OooO00o()V

    return-void

    :cond_5
    invoke-static {v3}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/gv4;

    check-cast v1, Llyiahf/vczjk/tv4;

    iget v1, v1, Llyiahf/vczjk/tv4;->OooOOOo:I

    iget p2, p2, Llyiahf/vczjk/sv4;->OooOO0o:I

    sub-int/2addr p2, v1

    int-to-float p2, p2

    cmpg-float p1, p2, p1

    if-gez p1, :cond_6

    iget-object p1, v0, Llyiahf/vczjk/o0OoOo0;->OooO0OO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/ju4;

    if-eqz p1, :cond_6

    invoke-interface {p1}, Llyiahf/vczjk/ju4;->OooO00o()V

    :cond_6
    return-void
.end method
