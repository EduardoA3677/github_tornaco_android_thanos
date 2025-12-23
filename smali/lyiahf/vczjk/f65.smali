.class public final Llyiahf/vczjk/f65;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $observer:Llyiahf/vczjk/bi9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bi9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/f65;->$observer:Llyiahf/vczjk/bi9;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/ky6;

    check-cast p2, Llyiahf/vczjk/p86;

    iget-wide p1, p2, Llyiahf/vczjk/p86;->OooO00o:J

    iget-object v0, p0, Llyiahf/vczjk/f65;->$observer:Llyiahf/vczjk/bi9;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/bi9;->OooO0Oo(J)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
