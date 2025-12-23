.class public final Llyiahf/vczjk/t95;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/w95;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/w95;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/t95;->this$0:Llyiahf/vczjk/w95;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/t95;->this$0:Llyiahf/vczjk/w95;

    iget-wide v0, v0, Llyiahf/vczjk/w95;->Oooo0:J

    new-instance v2, Llyiahf/vczjk/p86;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/p86;-><init>(J)V

    return-object v2
.end method
