.class public final Llyiahf/vczjk/ni9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $innerTextFieldCoordinates:Llyiahf/vczjk/xn4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xn4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ni9;->$innerTextFieldCoordinates:Llyiahf/vczjk/xn4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/ze5;

    iget-object p1, p1, Llyiahf/vczjk/ze5;->OooO00o:[F

    iget-object v0, p0, Llyiahf/vczjk/ni9;->$innerTextFieldCoordinates:Llyiahf/vczjk/xn4;

    invoke-interface {v0}, Llyiahf/vczjk/xn4;->OooOO0o()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ni9;->$innerTextFieldCoordinates:Llyiahf/vczjk/xn4;

    invoke-static {v0}, Llyiahf/vczjk/ng0;->OooOo0o(Llyiahf/vczjk/xn4;)Llyiahf/vczjk/xn4;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/ni9;->$innerTextFieldCoordinates:Llyiahf/vczjk/xn4;

    invoke-interface {v0, v1, p1}, Llyiahf/vczjk/xn4;->Oooo00O(Llyiahf/vczjk/xn4;[F)V

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
