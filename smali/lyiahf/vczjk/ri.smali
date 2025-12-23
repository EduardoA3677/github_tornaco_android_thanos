.class public final Llyiahf/vczjk/ri;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $animSpec$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $animatable:Llyiahf/vczjk/gi;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/gi;"
        }
    .end annotation
.end field

.field final synthetic $listener$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $newTarget:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field label:I


# direct methods
.method public constructor <init>(Ljava/lang/Object;Llyiahf/vczjk/gi;Llyiahf/vczjk/p29;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ri;->$newTarget:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/ri;->$animatable:Llyiahf/vczjk/gi;

    iput-object p3, p0, Llyiahf/vczjk/ri;->$animSpec$delegate:Llyiahf/vczjk/p29;

    iput-object p4, p0, Llyiahf/vczjk/ri;->$listener$delegate:Llyiahf/vczjk/p29;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/ri;

    iget-object v1, p0, Llyiahf/vczjk/ri;->$newTarget:Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/ri;->$animatable:Llyiahf/vczjk/gi;

    iget-object v3, p0, Llyiahf/vczjk/ri;->$animSpec$delegate:Llyiahf/vczjk/p29;

    iget-object v4, p0, Llyiahf/vczjk/ri;->$listener$delegate:Llyiahf/vczjk/p29;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/ri;-><init>(Ljava/lang/Object;Llyiahf/vczjk/gi;Llyiahf/vczjk/p29;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ri;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ri;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ri;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ri;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v7, p0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ri;->$newTarget:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/ri;->$animatable:Llyiahf/vczjk/gi;

    iget-object v1, v1, Llyiahf/vczjk/gi;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_3

    iget-object v3, p0, Llyiahf/vczjk/ri;->$animatable:Llyiahf/vczjk/gi;

    iget-object v4, p0, Llyiahf/vczjk/ri;->$newTarget:Ljava/lang/Object;

    iget-object p1, p0, Llyiahf/vczjk/ri;->$animSpec$delegate:Llyiahf/vczjk/p29;

    sget-object v1, Llyiahf/vczjk/ti;->OooO00o:Llyiahf/vczjk/wz8;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/wl;

    iput v2, p0, Llyiahf/vczjk/ri;->label:I

    const/4 v6, 0x0

    const/16 v8, 0xc

    move-object v7, p0

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/gi;->OooO0O0(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/wl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    iget-object p1, v7, Llyiahf/vczjk/ri;->$listener$delegate:Llyiahf/vczjk/p29;

    sget-object v0, Llyiahf/vczjk/ti;->OooO00o:Llyiahf/vczjk/wz8;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/oe3;

    if-eqz p1, :cond_4

    iget-object v0, v7, Llyiahf/vczjk/ri;->$animatable:Llyiahf/vczjk/gi;

    invoke-virtual {v0}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v0

    invoke-interface {p1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_1

    :cond_3
    move-object v7, p0

    :cond_4
    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
