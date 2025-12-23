.class public final Llyiahf/vczjk/c65;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $observer:Llyiahf/vczjk/bi9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bi9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/c65;->$observer:Llyiahf/vczjk/bi9;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/p86;

    iget-wide v0, p1, Llyiahf/vczjk/p86;->OooO00o:J

    iget-object p1, p0, Llyiahf/vczjk/c65;->$observer:Llyiahf/vczjk/bi9;

    invoke-interface {p1, v0, v1}, Llyiahf/vczjk/bi9;->OooO00o(J)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
