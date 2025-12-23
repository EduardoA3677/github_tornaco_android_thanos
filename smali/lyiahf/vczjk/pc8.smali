.class public final Llyiahf/vczjk/pc8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/xc8;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/xc8;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xc8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pc8;->this$0:Llyiahf/vczjk/xc8;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/pc8;->this$0:Llyiahf/vczjk/xc8;

    iget-object v1, v0, Llyiahf/vczjk/xc8;->OooO0o0:Llyiahf/vczjk/bz9;

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Llyiahf/vczjk/bz9;->OooO0oo()J

    move-result-wide v1

    goto :goto_0

    :cond_0
    const-wide/16 v1, 0x0

    :goto_0
    iput-wide v1, v0, Llyiahf/vczjk/xc8;->OooO0o:J

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
