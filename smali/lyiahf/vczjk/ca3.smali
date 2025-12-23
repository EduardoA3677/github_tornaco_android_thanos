.class public final Llyiahf/vczjk/ca3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/ea3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ea3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ca3;->this$0:Llyiahf/vczjk/ea3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/d6a;

    iget-object v0, p0, Llyiahf/vczjk/ca3;->this$0:Llyiahf/vczjk/ea3;

    iget-object v3, p1, Llyiahf/vczjk/d6a;->OooO0O0:Llyiahf/vczjk/ib3;

    new-instance v1, Llyiahf/vczjk/d6a;

    iget v5, p1, Llyiahf/vczjk/d6a;->OooO0Oo:I

    iget-object v6, p1, Llyiahf/vczjk/d6a;->OooO0o0:Ljava/lang/Object;

    const/4 v2, 0x0

    iget v4, p1, Llyiahf/vczjk/d6a;->OooO0OO:I

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/d6a;-><init>(Llyiahf/vczjk/ba3;Llyiahf/vczjk/ib3;IILjava/lang/Object;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ea3;->OooO00o(Llyiahf/vczjk/d6a;)Llyiahf/vczjk/i6a;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
