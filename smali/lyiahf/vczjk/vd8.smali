.class public final Llyiahf/vczjk/vd8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $observer:Llyiahf/vczjk/bi9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bi9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vd8;->$observer:Llyiahf/vczjk/bi9;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/ky6;

    iget-object v0, p0, Llyiahf/vczjk/vd8;->$observer:Llyiahf/vczjk/bi9;

    const/4 v1, 0x0

    invoke-static {p1, v1}, Llyiahf/vczjk/vl6;->OooOoo0(Llyiahf/vczjk/ky6;Z)J

    move-result-wide v1

    invoke-interface {v0, v1, v2}, Llyiahf/vczjk/bi9;->OooO0Oo(J)V

    invoke-virtual {p1}, Llyiahf/vczjk/ky6;->OooO00o()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
