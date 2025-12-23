.class public final Llyiahf/vczjk/ef2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/kf2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kf2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ef2;->this$0:Llyiahf/vczjk/kf2;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ef2;->this$0:Llyiahf/vczjk/kf2;

    invoke-virtual {v0}, Llyiahf/vczjk/kf2;->o0000O0()Z

    move-result v0

    xor-int/lit8 v0, v0, 0x1

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0
.end method
