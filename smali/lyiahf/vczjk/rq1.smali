.class public final Llyiahf/vczjk/rq1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $position:J


# direct methods
.method public constructor <init>(J)V
    .locals 0

    iput-wide p1, p0, Llyiahf/vczjk/rq1;->$position:J

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/af8;

    sget-object v0, Llyiahf/vczjk/zd8;->OooO0OO:Llyiahf/vczjk/ze8;

    new-instance v1, Llyiahf/vczjk/yd8;

    sget-object v2, Llyiahf/vczjk/tl3;->OooOOO0:Llyiahf/vczjk/tl3;

    iget-wide v3, p0, Llyiahf/vczjk/rq1;->$position:J

    sget-object v5, Llyiahf/vczjk/xd8;->OooOOO:Llyiahf/vczjk/xd8;

    const/4 v6, 0x1

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/yd8;-><init>(Llyiahf/vczjk/tl3;JLlyiahf/vczjk/xd8;Z)V

    check-cast p1, Llyiahf/vczjk/je8;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
