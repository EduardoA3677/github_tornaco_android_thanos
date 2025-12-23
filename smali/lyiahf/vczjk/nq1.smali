.class public final Llyiahf/vczjk/nq1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $manager:Llyiahf/vczjk/mk9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mk9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nq1;->$manager:Llyiahf/vczjk/mk9;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/p86;

    iget-wide v0, p1, Llyiahf/vczjk/p86;->OooO00o:J

    iget-object p1, p0, Llyiahf/vczjk/nq1;->$manager:Llyiahf/vczjk/mk9;

    invoke-virtual {p1}, Llyiahf/vczjk/mk9;->OooOOo()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
