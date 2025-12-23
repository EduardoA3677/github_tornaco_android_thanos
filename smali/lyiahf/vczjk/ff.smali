.class public final Llyiahf/vczjk/ff;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $popupLayout:Llyiahf/vczjk/zz6;

.field final synthetic $popupPositionProvider:Llyiahf/vczjk/c07;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zz6;Llyiahf/vczjk/c07;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ff;->$popupLayout:Llyiahf/vczjk/zz6;

    iput-object p2, p0, Llyiahf/vczjk/ff;->$popupPositionProvider:Llyiahf/vczjk/c07;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/ff;->$popupLayout:Llyiahf/vczjk/zz6;

    iget-object v0, p0, Llyiahf/vczjk/ff;->$popupPositionProvider:Llyiahf/vczjk/c07;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zz6;->setPositionProvider(Llyiahf/vczjk/c07;)V

    iget-object p1, p0, Llyiahf/vczjk/ff;->$popupLayout:Llyiahf/vczjk/zz6;

    invoke-virtual {p1}, Llyiahf/vczjk/zz6;->OooOOO()V

    new-instance p1, Llyiahf/vczjk/ef;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Llyiahf/vczjk/ef;-><init>(I)V

    return-object p1
.end method
