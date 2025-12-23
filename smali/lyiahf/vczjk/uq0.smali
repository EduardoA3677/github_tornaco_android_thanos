.class public final Llyiahf/vczjk/uq0;
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

.field final synthetic $target:F

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/vq0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gi;FZLlyiahf/vczjk/vq0;Llyiahf/vczjk/j24;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/uq0;->$animatable:Llyiahf/vczjk/gi;

    iput p2, p0, Llyiahf/vczjk/uq0;->$target:F

    iput-boolean p3, p0, Llyiahf/vczjk/uq0;->$enabled:Z

    iput-object p4, p0, Llyiahf/vczjk/uq0;->this$0:Llyiahf/vczjk/vq0;

    iput-object p5, p0, Llyiahf/vczjk/uq0;->$interaction:Llyiahf/vczjk/j24;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 7

    new-instance v0, Llyiahf/vczjk/uq0;

    iget-object v1, p0, Llyiahf/vczjk/uq0;->$animatable:Llyiahf/vczjk/gi;

    iget v2, p0, Llyiahf/vczjk/uq0;->$target:F

    iget-boolean v3, p0, Llyiahf/vczjk/uq0;->$enabled:Z

    iget-object v4, p0, Llyiahf/vczjk/uq0;->this$0:Llyiahf/vczjk/vq0;

    iget-object v5, p0, Llyiahf/vczjk/uq0;->$interaction:Llyiahf/vczjk/j24;

    move-object v6, p2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/uq0;-><init>(Llyiahf/vczjk/gi;FZLlyiahf/vczjk/vq0;Llyiahf/vczjk/j24;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/uq0;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uq0;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/uq0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/uq0;->label:I

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

    goto/16 :goto_3

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/uq0;->$animatable:Llyiahf/vczjk/gi;

    iget-object p1, p1, Llyiahf/vczjk/gi;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wd2;

    iget p1, p1, Llyiahf/vczjk/wd2;->OooOOO0:F

    iget v1, p0, Llyiahf/vczjk/uq0;->$target:F

    invoke-static {p1, v1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result p1

    if-nez p1, :cond_8

    iget-boolean p1, p0, Llyiahf/vczjk/uq0;->$enabled:Z

    if-nez p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/uq0;->$animatable:Llyiahf/vczjk/gi;

    iget v1, p0, Llyiahf/vczjk/uq0;->$target:F

    new-instance v2, Llyiahf/vczjk/wd2;

    invoke-direct {v2, v1}, Llyiahf/vczjk/wd2;-><init>(F)V

    iput v3, p0, Llyiahf/vczjk/uq0;->label:I

    invoke-virtual {p1, v2, p0}, Llyiahf/vczjk/gi;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_8

    goto :goto_2

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/uq0;->$animatable:Llyiahf/vczjk/gi;

    iget-object p1, p1, Llyiahf/vczjk/gi;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wd2;

    iget p1, p1, Llyiahf/vczjk/wd2;->OooOOO0:F

    iget-object v1, p0, Llyiahf/vczjk/uq0;->this$0:Llyiahf/vczjk/vq0;

    iget v1, v1, Llyiahf/vczjk/vq0;->OooO0O0:F

    invoke-static {p1, v1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v1

    if-eqz v1, :cond_4

    new-instance p1, Llyiahf/vczjk/q37;

    const-wide/16 v3, 0x0

    invoke-direct {p1, v3, v4}, Llyiahf/vczjk/q37;-><init>(J)V

    goto :goto_1

    :cond_4
    iget-object v1, p0, Llyiahf/vczjk/uq0;->this$0:Llyiahf/vczjk/vq0;

    iget v1, v1, Llyiahf/vczjk/vq0;->OooO0Oo:F

    invoke-static {p1, v1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v1

    if-eqz v1, :cond_5

    new-instance p1, Llyiahf/vczjk/wo3;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    goto :goto_1

    :cond_5
    iget-object v1, p0, Llyiahf/vczjk/uq0;->this$0:Llyiahf/vczjk/vq0;

    iget v1, v1, Llyiahf/vczjk/vq0;->OooO0OO:F

    invoke-static {p1, v1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v1

    if-eqz v1, :cond_6

    new-instance p1, Llyiahf/vczjk/g83;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    goto :goto_1

    :cond_6
    iget-object v1, p0, Llyiahf/vczjk/uq0;->this$0:Llyiahf/vczjk/vq0;

    iget v1, v1, Llyiahf/vczjk/vq0;->OooO0o0:F

    invoke-static {p1, v1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result p1

    if-eqz p1, :cond_7

    new-instance p1, Llyiahf/vczjk/mf2;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    goto :goto_1

    :cond_7
    const/4 p1, 0x0

    :goto_1
    iget-object v1, p0, Llyiahf/vczjk/uq0;->$animatable:Llyiahf/vczjk/gi;

    iget v3, p0, Llyiahf/vczjk/uq0;->$target:F

    iget-object v4, p0, Llyiahf/vczjk/uq0;->$interaction:Llyiahf/vczjk/j24;

    iput v2, p0, Llyiahf/vczjk/uq0;->label:I

    invoke-static {v1, v3, p1, v4, p0}, Llyiahf/vczjk/hl2;->OooO00o(Llyiahf/vczjk/gi;FLlyiahf/vczjk/j24;Llyiahf/vczjk/j24;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_8

    :goto_2
    return-object v0

    :cond_8
    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
