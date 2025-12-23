.class public final Llyiahf/vczjk/fu4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $pinnableItem:Llyiahf/vczjk/eu4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eu4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fu4;->$pinnableItem:Llyiahf/vczjk/eu4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/fu4;->$pinnableItem:Llyiahf/vczjk/eu4;

    new-instance v0, Llyiahf/vczjk/x;

    const/16 v1, 0x8

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/x;-><init>(Ljava/lang/Object;I)V

    return-object v0
.end method
