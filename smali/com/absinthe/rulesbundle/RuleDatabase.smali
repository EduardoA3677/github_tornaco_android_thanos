.class public abstract Lcom/absinthe/rulesbundle/RuleDatabase;
.super Llyiahf/vczjk/ru7;
.source "SourceFile"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008\'\u0018\u00002\u00020\u0001:\u0001\u0004B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u00a8\u0006\u0005"
    }
    d2 = {
        "Lcom/absinthe/rulesbundle/RuleDatabase;",
        "Llyiahf/vczjk/ru7;",
        "<init>",
        "()V",
        "lyiahf/vczjk/e86",
        "library_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final OooO00o:Llyiahf/vczjk/e86;

.field public static volatile OooO0O0:Lcom/absinthe/rulesbundle/RuleDatabase;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/e86;

    const/16 v1, 0x16

    invoke-direct {v0, v1}, Llyiahf/vczjk/e86;-><init>(I)V

    sput-object v0, Lcom/absinthe/rulesbundle/RuleDatabase;->OooO00o:Llyiahf/vczjk/e86;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/ru7;-><init>()V

    return-void
.end method


# virtual methods
.method public abstract OooO0O0()Llyiahf/vczjk/sw7;
.end method

.method public final close()V
    .locals 1

    invoke-super {p0}, Llyiahf/vczjk/ru7;->close()V

    const/4 v0, 0x0

    sput-object v0, Lcom/absinthe/rulesbundle/RuleDatabase;->OooO0O0:Lcom/absinthe/rulesbundle/RuleDatabase;

    return-void
.end method
