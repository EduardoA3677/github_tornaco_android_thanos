.class public final Llyiahf/vczjk/vz7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $countdown$delegate:Llyiahf/vczjk/qr5;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qr5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vz7;->$countdown$delegate:Llyiahf/vczjk/qr5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/vz7;

    iget-object v0, p0, Llyiahf/vczjk/vz7;->$countdown$delegate:Llyiahf/vczjk/qr5;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/vz7;-><init>(Llyiahf/vczjk/qr5;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/vz7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/vz7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/vz7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/vz7;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/vz7;->$countdown$delegate:Llyiahf/vczjk/qr5;

    check-cast p1, Llyiahf/vczjk/bw8;

    invoke-virtual {p1}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result p1

    if-lez p1, :cond_3

    iput v2, p0, Llyiahf/vczjk/vz7;->label:I

    const-wide/16 v3, 0x3e8

    invoke-static {v3, v4, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/vz7;->$countdown$delegate:Llyiahf/vczjk/qr5;

    check-cast p1, Llyiahf/vczjk/bw8;

    invoke-virtual {p1}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result p1

    iget-object v1, p0, Llyiahf/vczjk/vz7;->$countdown$delegate:Llyiahf/vczjk/qr5;

    add-int/lit8 p1, p1, -0x1

    check-cast v1, Llyiahf/vczjk/bw8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    goto :goto_0

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
