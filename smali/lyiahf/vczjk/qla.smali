.class public abstract Llyiahf/vczjk/qla;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static OooO00o(Landroid/webkit/WebSettings;I)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/sla;->OooOOO0:Llyiahf/vczjk/sla;

    invoke-virtual {v0}, Llyiahf/vczjk/sla;->OooO0O0()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-static {p0, p1}, Llyiahf/vczjk/hp7;->OooOoO0(Landroid/webkit/WebSettings;I)V

    return-void

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/sla;->OooO0OO()Z

    move-result v0

    if-eqz v0, :cond_1

    sget-object v0, Llyiahf/vczjk/tla;->OooO00o:Llyiahf/vczjk/fk7;

    iget-object v0, v0, Llyiahf/vczjk/fk7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Lorg/chromium/support_lib_boundary/WebkitToCompatConverterBoundaryInterface;

    invoke-interface {v0, p0}, Lorg/chromium/support_lib_boundary/WebkitToCompatConverterBoundaryInterface;->convertSettings(Landroid/webkit/WebSettings;)Ljava/lang/reflect/InvocationHandler;

    move-result-object p0

    const-class v0, Lorg/chromium/support_lib_boundary/WebSettingsBoundaryInterface;

    invoke-static {v0, p0}, Llyiahf/vczjk/tg0;->OooOo0O(Ljava/lang/Class;Ljava/lang/reflect/InvocationHandler;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lorg/chromium/support_lib_boundary/WebSettingsBoundaryInterface;

    invoke-interface {p0, p1}, Lorg/chromium/support_lib_boundary/WebSettingsBoundaryInterface;->setForceDark(I)V

    return-void

    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    const-string p1, "This method is not supported by the current version of the framework and the current WebView APK"

    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p0
.end method
