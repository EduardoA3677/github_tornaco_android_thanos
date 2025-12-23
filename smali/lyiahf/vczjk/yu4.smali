.class public final Llyiahf/vczjk/yu4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/zu4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zu4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yu4;->this$0:Llyiahf/vczjk/zu4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/yu4;->this$0:Llyiahf/vczjk/zu4;

    iget-object v0, v0, Llyiahf/vczjk/zu4;->OooOoOO:Llyiahf/vczjk/hh4;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nt4;

    if-ltz p1, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/nt4;->OooO00o()I

    move-result v1

    if-ge p1, v1, :cond_0

    goto :goto_0

    :cond_0
    const-string v1, "Can\'t scroll to index "

    const-string v2, ", it is out of bounds [0, "

    invoke-static {p1, v1, v2}, Llyiahf/vczjk/ii5;->OooOOO(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-interface {v0}, Llyiahf/vczjk/nt4;->OooO00o()I

    move-result v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const/16 v0, 0x29

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/sz3;->OooO00o(Ljava/lang/String;)V

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/yu4;->this$0:Llyiahf/vczjk/zu4;

    invoke-virtual {v0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/xu4;

    iget-object v2, p0, Llyiahf/vczjk/yu4;->this$0:Llyiahf/vczjk/zu4;

    const/4 v3, 0x0

    invoke-direct {v1, v2, p1, v3}, Llyiahf/vczjk/xu4;-><init>(Llyiahf/vczjk/zu4;ILlyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v0, v3, v3, v1, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1
.end method
