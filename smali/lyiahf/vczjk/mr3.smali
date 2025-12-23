.class public final Llyiahf/vczjk/mr3;
.super Llyiahf/vczjk/rs7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $onHueChanged:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/mr3;->$onHueChanged:Llyiahf/vczjk/oe3;

    invoke-direct {p0, p1}, Llyiahf/vczjk/rs7;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/mr3;

    iget-object v1, p0, Llyiahf/vczjk/mr3;->$onHueChanged:Llyiahf/vczjk/oe3;

    invoke-direct {v0, p2, v1}, Llyiahf/vczjk/mr3;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)V

    iput-object p1, v0, Llyiahf/vczjk/mr3;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/kb9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/mr3;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/mr3;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/mr3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/mr3;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/mr3;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/kb9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/mr3;->L$0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/kb9;

    iput-object v1, p0, Llyiahf/vczjk/mr3;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/mr3;->label:I

    const/4 p1, 0x3

    invoke-static {v1, p0, p1}, Llyiahf/vczjk/dg9;->OooO0OO(Llyiahf/vczjk/kb9;Llyiahf/vczjk/rs7;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    :goto_0
    check-cast p1, Llyiahf/vczjk/ky6;

    iget-object v3, p0, Llyiahf/vczjk/mr3;->$onHueChanged:Llyiahf/vczjk/oe3;

    iget-wide v4, p1, Llyiahf/vczjk/ky6;->OooO0OO:J

    const-wide v6, 0xffffffffL

    and-long/2addr v4, v6

    long-to-int v4, v4

    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v4

    iget-object v5, v1, Llyiahf/vczjk/kb9;->OooOOo:Llyiahf/vczjk/nb9;

    iget-wide v8, v5, Llyiahf/vczjk/nb9;->Oooo0O0:J

    and-long v5, v8, v6

    long-to-int v5, v5

    int-to-float v5, v5

    const/4 v6, 0x0

    invoke-static {v4, v6, v5}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result v4

    const/high16 v6, 0x43b40000    # 360.0f

    mul-float/2addr v4, v6

    div-float/2addr v4, v5

    sub-float/2addr v6, v4

    new-instance v4, Ljava/lang/Float;

    invoke-direct {v4, v6}, Ljava/lang/Float;-><init>(F)V

    invoke-interface {v3, v4}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v3, p0, Llyiahf/vczjk/mr3;->$onHueChanged:Llyiahf/vczjk/oe3;

    new-instance v4, Llyiahf/vczjk/z6;

    const/4 v5, 0x1

    invoke-direct {v4, v3, v1, v5}, Llyiahf/vczjk/z6;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/kb9;I)V

    const/4 v3, 0x0

    iput-object v3, p0, Llyiahf/vczjk/mr3;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/mr3;->label:I

    iget-wide v2, p1, Llyiahf/vczjk/ky6;->OooO00o:J

    invoke-static {v1, v2, v3, v4, p0}, Llyiahf/vczjk/ve2;->OooO0OO(Llyiahf/vczjk/kb9;JLlyiahf/vczjk/oe3;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_1
    return-object v0

    :cond_4
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
