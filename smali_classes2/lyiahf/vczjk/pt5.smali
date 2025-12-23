.class public final synthetic Llyiahf/vczjk/pt5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:J

.field public final synthetic OooOOO0:J

.field public final synthetic OooOOOO:Ljava/lang/String;

.field public final synthetic OooOOOo:I

.field public final synthetic OooOOo0:I


# direct methods
.method public synthetic constructor <init>(IIJJLjava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p3, p0, Llyiahf/vczjk/pt5;->OooOOO0:J

    iput-wide p5, p0, Llyiahf/vczjk/pt5;->OooOOO:J

    iput-object p7, p0, Llyiahf/vczjk/pt5;->OooOOOO:Ljava/lang/String;

    iput p1, p0, Llyiahf/vczjk/pt5;->OooOOOo:I

    iput p2, p0, Llyiahf/vczjk/pt5;->OooOOo0:I

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/j48;

    iget-object v4, p0, Llyiahf/vczjk/pt5;->OooOOOO:Ljava/lang/String;

    iget v5, p0, Llyiahf/vczjk/pt5;->OooOOOo:I

    iget-wide v0, p0, Llyiahf/vczjk/pt5;->OooOOO0:J

    iget-wide v2, p0, Llyiahf/vczjk/pt5;->OooOOO:J

    iget v6, p0, Llyiahf/vczjk/pt5;->OooOOo0:I

    invoke-static/range {v0 .. v7}, Lgithub/tornaco/android/thanos/db/n/NRDao_Impl;->OooO0OO(JJLjava/lang/String;IILlyiahf/vczjk/j48;)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method
