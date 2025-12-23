.class public final Llyiahf/vczjk/hf9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $down:Llyiahf/vczjk/ky6;

.field final synthetic $onPress:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $pressScope:Llyiahf/vczjk/o37;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/o37;Llyiahf/vczjk/ky6;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hf9;->$onPress:Llyiahf/vczjk/bf3;

    iput-object p2, p0, Llyiahf/vczjk/hf9;->$pressScope:Llyiahf/vczjk/o37;

    iput-object p3, p0, Llyiahf/vczjk/hf9;->$down:Llyiahf/vczjk/ky6;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/hf9;

    iget-object v0, p0, Llyiahf/vczjk/hf9;->$onPress:Llyiahf/vczjk/bf3;

    iget-object v1, p0, Llyiahf/vczjk/hf9;->$pressScope:Llyiahf/vczjk/o37;

    iget-object v2, p0, Llyiahf/vczjk/hf9;->$down:Llyiahf/vczjk/ky6;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/hf9;-><init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/o37;Llyiahf/vczjk/ky6;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/hf9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/hf9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/hf9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/hf9;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/hf9;->$onPress:Llyiahf/vczjk/bf3;

    iget-object v1, p0, Llyiahf/vczjk/hf9;->$pressScope:Llyiahf/vczjk/o37;

    iget-object v3, p0, Llyiahf/vczjk/hf9;->$down:Llyiahf/vczjk/ky6;

    iget-wide v3, v3, Llyiahf/vczjk/ky6;->OooO0OO:J

    new-instance v5, Llyiahf/vczjk/p86;

    invoke-direct {v5, v3, v4}, Llyiahf/vczjk/p86;-><init>(J)V

    iput v2, p0, Llyiahf/vczjk/hf9;->label:I

    invoke-interface {p1, v1, v5, p0}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
