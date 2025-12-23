.class public final Llyiahf/vczjk/asa;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $align:Llyiahf/vczjk/o4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/o4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/asa;->$align:Llyiahf/vczjk/o4;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/b24;

    iget-wide v3, p1, Llyiahf/vczjk/b24;->OooO00o:J

    move-object v5, p2

    check-cast v5, Llyiahf/vczjk/yn4;

    iget-object v0, p0, Llyiahf/vczjk/asa;->$align:Llyiahf/vczjk/o4;

    const-wide/16 v1, 0x0

    invoke-interface/range {v0 .. v5}, Llyiahf/vczjk/o4;->OooO00o(JJLlyiahf/vczjk/yn4;)J

    move-result-wide p1

    new-instance v0, Llyiahf/vczjk/u14;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/u14;-><init>(J)V

    return-object v0
.end method
