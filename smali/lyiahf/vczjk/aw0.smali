.class public final Llyiahf/vczjk/aw0;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $animatable:Llyiahf/vczjk/gi;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/gi;"
        }
    .end annotation
.end field

.field final synthetic $enabled:Z

.field final synthetic $interaction:Llyiahf/vczjk/j24;

.field final synthetic $lastInteraction$delegate:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field

.field final synthetic $target:F

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gi;FZLlyiahf/vczjk/j24;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/aw0;->$animatable:Llyiahf/vczjk/gi;

    iput p2, p0, Llyiahf/vczjk/aw0;->$target:F

    iput-boolean p3, p0, Llyiahf/vczjk/aw0;->$enabled:Z

    iput-object p4, p0, Llyiahf/vczjk/aw0;->$interaction:Llyiahf/vczjk/j24;

    iput-object p5, p0, Llyiahf/vczjk/aw0;->$lastInteraction$delegate:Llyiahf/vczjk/qs5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/aw0;

    iget-object v1, p0, Llyiahf/vczjk/aw0;->$animatable:Llyiahf/vczjk/gi;

    iget v2, p0, Llyiahf/vczjk/aw0;->$target:F

    iget-boolean v3, p0, Llyiahf/vczjk/aw0;->$enabled:Z

    iget-object v4, p0, Llyiahf/vczjk/aw0;->$interaction:Llyiahf/vczjk/j24;

    iget-object v5, p0, Llyiahf/vczjk/aw0;->$lastInteraction$delegate:Llyiahf/vczjk/qs5;

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/aw0;-><init>(Llyiahf/vczjk/gi;FZLlyiahf/vczjk/j24;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/aw0;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/aw0;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/aw0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/aw0;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/aw0;->$animatable:Llyiahf/vczjk/gi;

    iget-object p1, p1, Llyiahf/vczjk/gi;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wd2;

    iget p1, p1, Llyiahf/vczjk/wd2;->OooOOO0:F

    iget v1, p0, Llyiahf/vczjk/aw0;->$target:F

    invoke-static {p1, v1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result p1

    if-nez p1, :cond_5

    iget-boolean p1, p0, Llyiahf/vczjk/aw0;->$enabled:Z

    if-nez p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/aw0;->$animatable:Llyiahf/vczjk/gi;

    iget v1, p0, Llyiahf/vczjk/aw0;->$target:F

    new-instance v2, Llyiahf/vczjk/wd2;

    invoke-direct {v2, v1}, Llyiahf/vczjk/wd2;-><init>(F)V

    iput v3, p0, Llyiahf/vczjk/aw0;->label:I

    invoke-virtual {p1, v2, p0}, Llyiahf/vczjk/gi;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    goto :goto_1

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/aw0;->$lastInteraction$delegate:Llyiahf/vczjk/qs5;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/j24;

    iget-object v1, p0, Llyiahf/vczjk/aw0;->$animatable:Llyiahf/vczjk/gi;

    iget v3, p0, Llyiahf/vczjk/aw0;->$target:F

    iget-object v4, p0, Llyiahf/vczjk/aw0;->$interaction:Llyiahf/vczjk/j24;

    iput v2, p0, Llyiahf/vczjk/aw0;->label:I

    invoke-static {v1, v3, p1, v4, p0}, Llyiahf/vczjk/hl2;->OooO00o(Llyiahf/vczjk/gi;FLlyiahf/vczjk/j24;Llyiahf/vczjk/j24;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_1
    return-object v0

    :cond_4
    :goto_2
    iget-object p1, p0, Llyiahf/vczjk/aw0;->$lastInteraction$delegate:Llyiahf/vczjk/qs5;

    iget-object v0, p0, Llyiahf/vczjk/aw0;->$interaction:Llyiahf/vczjk/j24;

    invoke-interface {p1, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    :cond_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
