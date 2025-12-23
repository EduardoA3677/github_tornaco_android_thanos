.class public final Llyiahf/vczjk/az9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/az9;->this$0:Llyiahf/vczjk/bz9;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/az9;->this$0:Llyiahf/vczjk/bz9;

    invoke-virtual {v0}, Llyiahf/vczjk/bz9;->OooO0O0()J

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v0

    return-object v0
.end method
