.class public final Llyiahf/vczjk/sn1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $onOpenGesture:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $state:Llyiahf/vczjk/eo1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/eo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sn1;->$onOpenGesture:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/sn1;->$state:Llyiahf/vczjk/eo1;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/p86;

    iget-wide v0, p1, Llyiahf/vczjk/p86;->OooO00o:J

    iget-object p1, p0, Llyiahf/vczjk/sn1;->$onOpenGesture:Llyiahf/vczjk/le3;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    iget-object p1, p0, Llyiahf/vczjk/sn1;->$state:Llyiahf/vczjk/eo1;

    new-instance v2, Llyiahf/vczjk/co1;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/co1;-><init>(J)V

    iget-object p1, p1, Llyiahf/vczjk/eo1;->OooO00o:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
