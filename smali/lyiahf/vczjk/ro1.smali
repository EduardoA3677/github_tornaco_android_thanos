.class public final Llyiahf/vczjk/ro1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $label:Llyiahf/vczjk/uh9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/uh9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ro1;->$label:Llyiahf/vczjk/uh9;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    check-cast p1, Llyiahf/vczjk/zf1;

    const p2, -0x67ff3d82

    invoke-virtual {p1, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p2, p0, Llyiahf/vczjk/ro1;->$label:Llyiahf/vczjk/uh9;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/uh9;->OooO00o(Llyiahf/vczjk/zf1;)Ljava/lang/String;

    move-result-object p2

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object p2
.end method
