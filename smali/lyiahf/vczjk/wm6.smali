.class public final Llyiahf/vczjk/wm6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/o23;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/hg9;

.field public final OooO0O0:Llyiahf/vczjk/lm6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hg9;Llyiahf/vczjk/lm6;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wm6;->OooO00o:Llyiahf/vczjk/hg9;

    iput-object p2, p0, Llyiahf/vczjk/wm6;->OooO0O0:Llyiahf/vczjk/lm6;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/xa8;FLlyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 5

    instance-of v0, p3, Llyiahf/vczjk/um6;

    if-eqz v0, :cond_0

    move-object v0, p3

    check-cast v0, Llyiahf/vczjk/um6;

    iget v1, v0, Llyiahf/vczjk/um6;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/um6;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/um6;

    check-cast p3, Llyiahf/vczjk/zo1;

    invoke-direct {v0, p0, p3}, Llyiahf/vczjk/um6;-><init>(Llyiahf/vczjk/wm6;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p3, v0, Llyiahf/vczjk/um6;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/um6;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/um6;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/wm6;

    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance p3, Llyiahf/vczjk/vm6;

    invoke-direct {p3, p0, p1}, Llyiahf/vczjk/vm6;-><init>(Llyiahf/vczjk/wm6;Llyiahf/vczjk/xa8;)V

    iput-object p0, v0, Llyiahf/vczjk/um6;->L$0:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/um6;->label:I

    iget-object v2, p0, Llyiahf/vczjk/wm6;->OooO00o:Llyiahf/vczjk/hg9;

    check-cast v2, Llyiahf/vczjk/wu8;

    invoke-virtual {v2, p1, p2, p3, v0}, Llyiahf/vczjk/wu8;->OooO0Oo(Llyiahf/vczjk/xa8;FLlyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p3

    if-ne p3, v1, :cond_3

    return-object v1

    :cond_3
    move-object p1, p0

    :goto_1
    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    move-result p2

    iget-object p3, p1, Llyiahf/vczjk/wm6;->OooO0O0:Llyiahf/vczjk/lm6;

    iget-object p3, p3, Llyiahf/vczjk/lm6;->OooO0Oo:Llyiahf/vczjk/oO00O0o;

    invoke-virtual {p3}, Llyiahf/vczjk/oO00O0o;->OooO0oO()F

    move-result p3

    const/4 v0, 0x0

    cmpg-float p3, p3, v0

    iget-object p1, p1, Llyiahf/vczjk/wm6;->OooO0O0:Llyiahf/vczjk/lm6;

    if-nez p3, :cond_4

    goto :goto_2

    :cond_4
    iget-object p3, p1, Llyiahf/vczjk/lm6;->OooO0Oo:Llyiahf/vczjk/oO00O0o;

    invoke-virtual {p3}, Llyiahf/vczjk/oO00O0o;->OooO0oO()F

    move-result p3

    invoke-static {p3}, Ljava/lang/Math;->abs(F)F

    move-result p3

    float-to-double v1, p3

    const-wide v3, 0x3f50624dd2f1a9fcL    # 0.001

    cmpg-double p3, v1, v3

    if-gez p3, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/lm6;->OooOO0()I

    move-result p3

    iget-object v1, p1, Llyiahf/vczjk/lm6;->OooOO0O:Llyiahf/vczjk/u32;

    invoke-virtual {v1}, Llyiahf/vczjk/u32;->OooO00o()Z

    move-result v1

    if-eqz v1, :cond_5

    iget-object v1, p1, Llyiahf/vczjk/lm6;->OooOOOo:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ol6;

    iget-object v1, v1, Llyiahf/vczjk/ol6;->OooOo00:Llyiahf/vczjk/xr1;

    new-instance v2, Llyiahf/vczjk/cm6;

    const/4 v3, 0x0

    invoke-direct {v2, p1, v3}, Llyiahf/vczjk/cm6;-><init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/yo1;)V

    const/4 v4, 0x3

    invoke-static {v1, v3, v3, v2, v4}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_5
    const/4 v1, 0x0

    invoke-virtual {p1, v0, p3, v1}, Llyiahf/vczjk/lm6;->OooOOoo(FIZ)V

    goto :goto_3

    :cond_6
    :goto_2
    iget-object p1, p1, Llyiahf/vczjk/lm6;->OooO0Oo:Llyiahf/vczjk/oO00O0o;

    invoke-virtual {p1}, Llyiahf/vczjk/oO00O0o;->OooO0oO()F

    :goto_3
    new-instance p1, Ljava/lang/Float;

    invoke-direct {p1, p2}, Ljava/lang/Float;-><init>(F)V

    return-object p1
.end method
