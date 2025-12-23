.class public final Llyiahf/vczjk/bh;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $coreModifier:Llyiahf/vczjk/kl5;

.field final synthetic $layoutNode:Llyiahf/vczjk/ro4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ro4;Llyiahf/vczjk/kl5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bh;->$layoutNode:Llyiahf/vczjk/ro4;

    iput-object p2, p0, Llyiahf/vczjk/bh;->$coreModifier:Llyiahf/vczjk/kl5;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/kl5;

    iget-object v0, p0, Llyiahf/vczjk/bh;->$layoutNode:Llyiahf/vczjk/ro4;

    iget-object v1, p0, Llyiahf/vczjk/bh;->$coreModifier:Llyiahf/vczjk/kl5;

    invoke-interface {p1, v1}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ro4;->Ooooo0o(Llyiahf/vczjk/kl5;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
