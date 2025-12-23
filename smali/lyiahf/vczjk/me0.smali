.class public final Llyiahf/vczjk/me0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $brush:Llyiahf/vczjk/ri0;

.field final synthetic $outline:Llyiahf/vczjk/of6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/of6;Llyiahf/vczjk/gx8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/me0;->$outline:Llyiahf/vczjk/of6;

    iput-object p2, p0, Llyiahf/vczjk/me0;->$brush:Llyiahf/vczjk/ri0;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/mm1;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/to4;

    invoke-virtual {v0}, Llyiahf/vczjk/to4;->OooO00o()V

    iget-object p1, p0, Llyiahf/vczjk/me0;->$outline:Llyiahf/vczjk/of6;

    iget-object v1, p1, Llyiahf/vczjk/of6;->OooO:Llyiahf/vczjk/qe;

    iget-object v2, p0, Llyiahf/vczjk/me0;->$brush:Llyiahf/vczjk/ri0;

    const/4 v4, 0x0

    const/16 v5, 0x3c

    const/4 v3, 0x0

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/hg2;->OoooOOO(Llyiahf/vczjk/hg2;Llyiahf/vczjk/bq6;Llyiahf/vczjk/ri0;FLlyiahf/vczjk/h79;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
