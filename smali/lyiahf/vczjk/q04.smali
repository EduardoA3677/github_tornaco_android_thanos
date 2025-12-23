.class public final Llyiahf/vczjk/q04;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/r04;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/r04;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/q04;->this$0:Llyiahf/vczjk/r04;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/z46;

    iget-object v0, p1, Llyiahf/vczjk/z46;->OooO0O0:Llyiahf/vczjk/rj7;

    if-eqz v0, :cond_0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/z46;->OooO00o(Llyiahf/vczjk/rj7;)V

    const/4 v0, 0x0

    iput-object v0, p1, Llyiahf/vczjk/z46;->OooO0O0:Llyiahf/vczjk/rj7;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/q04;->this$0:Llyiahf/vczjk/r04;

    iget-object v0, v0, Llyiahf/vczjk/r04;->OooO0Oo:Llyiahf/vczjk/ws5;

    iget-object v1, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v0, :cond_2

    aget-object v3, v1, v2

    check-cast v3, Llyiahf/vczjk/ola;

    invoke-static {v3, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    goto :goto_1

    :cond_1
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_2
    const/4 v2, -0x1

    :goto_1
    if-ltz v2, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/q04;->this$0:Llyiahf/vczjk/r04;

    iget-object p1, p1, Llyiahf/vczjk/r04;->OooO0Oo:Llyiahf/vczjk/ws5;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/ws5;->OooOO0O(I)Ljava/lang/Object;

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/q04;->this$0:Llyiahf/vczjk/r04;

    iget-object v0, p1, Llyiahf/vczjk/r04;->OooO0Oo:Llyiahf/vczjk/ws5;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    if-nez v0, :cond_4

    iget-object p1, p1, Llyiahf/vczjk/r04;->OooO0O0:Llyiahf/vczjk/we;

    invoke-virtual {p1}, Llyiahf/vczjk/we;->OooO00o()Ljava/lang/Object;

    :cond_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
