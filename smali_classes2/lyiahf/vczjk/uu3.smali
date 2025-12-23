.class public final Llyiahf/vczjk/uu3;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $executeImageRequest:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $state$delegate:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/uu3;->$executeImageRequest:Llyiahf/vczjk/oe3;

    iput-object p2, p0, Llyiahf/vczjk/uu3;->$state$delegate:Llyiahf/vczjk/qs5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/uu3;

    iget-object v0, p0, Llyiahf/vczjk/uu3;->$executeImageRequest:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/uu3;->$state$delegate:Llyiahf/vczjk/qs5;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/uu3;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/uu3;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uu3;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/uu3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/uu3;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/uu3;->$executeImageRequest:Llyiahf/vczjk/oe3;

    sget v1, Llyiahf/vczjk/yu3;->OooO00o:I

    new-instance v1, Llyiahf/vczjk/wu3;

    const/4 v3, 0x0

    invoke-direct {v1, v3, p1}, Llyiahf/vczjk/wu3;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)V

    new-instance p1, Llyiahf/vczjk/s48;

    invoke-direct {p1, v1}, Llyiahf/vczjk/s48;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v1, Llyiahf/vczjk/xu3;

    const/4 v4, 0x3

    invoke-direct {v1, v4, v3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    new-instance v3, Llyiahf/vczjk/n53;

    invoke-direct {v3, p1, v1}, Llyiahf/vczjk/n53;-><init>(Llyiahf/vczjk/s48;Llyiahf/vczjk/xu3;)V

    invoke-static {v3}, Llyiahf/vczjk/rs;->OooOo0(Llyiahf/vczjk/f43;)Llyiahf/vczjk/f43;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/fx6;->OooO00o:Llyiahf/vczjk/m22;

    invoke-static {p1, v1}, Llyiahf/vczjk/rs;->OooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/qr1;)Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/od;

    iget-object v3, p0, Llyiahf/vczjk/uu3;->$state$delegate:Llyiahf/vczjk/qs5;

    const/16 v4, 0x8

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/od;-><init>(Ljava/lang/Object;I)V

    iput v2, p0, Llyiahf/vczjk/uu3;->label:I

    invoke-interface {p1, v1, p0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
