.class public final Llyiahf/vczjk/re2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $onDragStart:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/c65;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/re2;->$onDragStart:Llyiahf/vczjk/oe3;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/ky6;

    check-cast p2, Llyiahf/vczjk/ky6;

    check-cast p3, Llyiahf/vczjk/p86;

    iget-wide v0, p3, Llyiahf/vczjk/p86;->OooO00o:J

    iget-object p1, p0, Llyiahf/vczjk/re2;->$onDragStart:Llyiahf/vczjk/oe3;

    iget-wide p2, p2, Llyiahf/vczjk/ky6;->OooO0OO:J

    new-instance v0, Llyiahf/vczjk/p86;

    invoke-direct {v0, p2, p3}, Llyiahf/vczjk/p86;-><init>(J)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
